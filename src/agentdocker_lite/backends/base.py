"""Base classes for agentdocker-lite sandboxes."""

from __future__ import annotations

import abc
import logging
import os
import shlex
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from agentdocker_lite._shell import _PersistentShell

logger = logging.getLogger(__name__)


# ====================================================================== #
#  Configuration                                                          #
# ====================================================================== #


def _parse_size(value: str) -> str:
    """Parse human-readable size to bytes string.

    Supports: "512m", "2g", "1.5G", "4096", "536870912".
    Returns the value as a string of bytes for cgroup writes.
    """
    value = value.strip()
    if not value:
        return value
    suffixes = {"k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}
    last = value[-1].lower()
    if last in suffixes:
        return str(int(float(value[:-1]) * suffixes[last]))
    return value


@dataclass
class SandboxConfig:
    """Configuration for a sandbox instance.

    Args:
        image: Path to a rootfs directory, or a Docker image name
            (e.g. ``"ubuntu:22.04"``).  If a Docker image name is given,
            it will be auto-exported to a rootfs directory on first use.
        working_dir: Initial working directory inside the sandbox.
        environment: Extra environment variables for commands.
        volumes: Volume mount specs as ``["host:container:mode", ...]``.
        fs_backend: Filesystem backend: ``"overlayfs"`` (default) or ``"btrfs"``.
        env_base_dir: Base directory for per-sandbox state.
        rootfs_cache_dir: Directory to cache auto-prepared rootfs images.
            Defaults to ``$XDG_CACHE_HOME/agentdocker_lite/rootfs``
            (typically ``~/.cache/agentdocker_lite/rootfs``).
        cpu_max: cgroup v2 ``cpu.max`` value (e.g. ``"50000 100000"``).
        memory_max: cgroup v2 ``memory.max`` value in bytes.
        pids_max: cgroup v2 ``pids.max`` value.
        tty: Use a pseudo-terminal instead of pipes for command I/O.
            Enables ``write_stdin()`` for interactive programs.  Default
            ``False`` preserves the fast pipe-based path.
        net_isolate: Create a separate network namespace (loopback only).
            Default ``False`` inherits the host network.
        devices: Host device paths to bind-mount into the sandbox
            (e.g. ``["/dev/kvm"]``).
        seccomp: Enable seccomp-bpf filter to block dangerous syscalls
            (ptrace, mount, kexec, bpf, etc.). Default ``True``.
        landlock_read: Paths allowed for read-only access under Landlock.
            If set, all other paths are denied. ``None`` disables Landlock.
        landlock_write: Paths allowed for read-write access under Landlock.
        landlock_tcp_ports: TCP ports allowed for connect under Landlock.
            ``None`` means no network restriction.
        hostname: Hostname inside the sandbox (UTS namespace).
            ``None`` uses the host's hostname.
        dns: Custom DNS servers (e.g. ``["8.8.8.8", "1.1.1.1"]``).
            Writes ``/etc/resolv.conf`` inside the sandbox.
            ``None`` inherits from host.
        read_only: Make the root filesystem read-only.  Writes are
            only allowed to volumes and tmpfs mounts.
        io_max: cgroup v2 ``io.max`` value for disk I/O throttling
            (e.g. ``"259:0 wbps=10485760"`` for 10MB/s write on device 259:0).
        port_map: Port mappings as ``["host_port:container_port", ...]``.
            Requires ``pasta`` (from the ``passt`` package). Automatically
            enables network isolation with NAT'd internet access.
    """

    image: str = ""
    working_dir: str = "/"
    environment: dict[str, str] = field(default_factory=dict)
    volumes: list[str] = field(default_factory=list)
    devices: list[str] = field(default_factory=list)
    fs_backend: str = "overlayfs"
    env_base_dir: str = "/tmp/agentdocker_lite"
    rootfs_cache_dir: str = ""  # resolved in __post_init__
    cpu_max: Optional[str] = None
    memory_max: Optional[str] = None
    pids_max: Optional[str] = None
    io_max: Optional[str] = None
    tty: bool = False
    net_isolate: bool = False
    seccomp: bool = True
    hostname: Optional[str] = None
    dns: Optional[list[str]] = None
    read_only: bool = False
    port_map: Optional[list[str]] = None
    landlock_read: Optional[list[str]] = None
    landlock_write: Optional[list[str]] = None
    landlock_tcp_ports: Optional[list[int]] = None
    oom_score_adj: Optional[int] = None
    cpuset_cpus: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.rootfs_cache_dir:
            cache_home = os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache"))
            self.rootfs_cache_dir = os.path.join(cache_home, "agentdocker_lite", "rootfs")
        # Parse human-readable sizes (e.g. "512m", "2g") to bytes.
        if self.memory_max:
            self.memory_max = _parse_size(self.memory_max)


# ====================================================================== #
#  Abstract base                                                          #
# ====================================================================== #


class SandboxBase(abc.ABC):
    """Abstract base class for sandbox implementations.

    Concrete shared methods (run, read_file, write_file, etc.) delegate
    to ``self._persistent_shell``.  Subclasses must implement
    ``reset()`` and ``delete()`` as well as their own ``__init__``.
    """

    # -- global registry for atexit cleanup -------------------------------- #
    _live_instances: list[SandboxBase] = []
    _atexit_registered: bool = False

    @classmethod
    def _register(cls, instance: SandboxBase) -> None:
        """Track a live sandbox for atexit cleanup."""
        cls._live_instances.append(instance)
        if not cls._atexit_registered:
            import atexit
            atexit.register(cls._atexit_cleanup)
            cls._atexit_registered = True

    @classmethod
    def _unregister(cls, instance: SandboxBase) -> None:
        """Remove a sandbox from the live registry."""
        try:
            cls._live_instances.remove(instance)
        except ValueError:
            pass

    @classmethod
    def _atexit_cleanup(cls) -> None:
        """Delete all live sandboxes on process exit."""
        for sb in list(cls._live_instances):
            try:
                sb.delete()
            except Exception:
                pass
        cls._live_instances.clear()

    # -- attributes set by subclass __init__ ------------------------------- #
    _config: SandboxConfig
    _name: str
    _rootfs: Path
    _env_dir: Path
    _shell: str
    _cached_env: dict[str, str]
    _persistent_shell: _PersistentShell
    _bg_handles: dict[str, str]
    _userns: bool

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def run(
        self, command: str | list[str], timeout: Optional[int] = None
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

    def write_stdin(self, data: str | bytes) -> None:
        """Write raw data to the sandbox shell's stdin (PTY mode only).

        Use this to send input to interactive programs.  Requires
        ``SandboxConfig(tty=True)``.

        Example::

            sb.run("cat")         # blocks waiting for stdin
            sb.write_stdin("hello\\n")
        """
        self._persistent_shell.write_stdin(data)

    # -- background processes ---------------------------------------------- #

    def run_background(self, command: str | list[str]) -> str:
        """Start a command in the background inside the sandbox.

        Returns a handle string to use with :meth:`check_background` and
        :meth:`stop_background`.  The command runs asynchronously; the
        persistent shell remains available for ``run()`` calls.

        Example::

            handle = sb.run_background("python -m http.server 8080")
            time.sleep(1)
            output, running = sb.check_background(handle)
        """
        if isinstance(command, list):
            command = shlex.join(command)
        handle = uuid.uuid4().hex[:8]
        out_file = f"/tmp/.bg_{handle}.out"
        pid_file = f"/tmp/.bg_{handle}.pid"
        self.run(
            f"nohup bash -c {shlex.quote(command)} > {out_file} 2>&1 & echo $! > {pid_file}"
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

    def list_background(self) -> dict[str, dict]:
        """List all background processes and their status.

        Returns a dict mapping handle to ``{"pid": str, "running": bool}``.
        """
        result = {}
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
        **kwargs,
    ) -> subprocess.Popen:
        """Start an interactive process inside the sandbox with stdio pipes.

        Unlike :meth:`run` (which aggregates output) and :meth:`run_background`
        (which redirects to a file), this returns a :class:`subprocess.Popen`
        object with direct ``stdin``/``stdout``/``stderr`` pipes for
        bidirectional communication.

        Useful for long-running interactive processes like LSP servers, REPLs,
        or any protocol that requires streaming stdin/stdout (e.g. JSON-RPC).

        The process runs inside the sandbox's namespace (PID + mount isolation)
        and chroot, sharing the same filesystem view as :meth:`run`.

        Args:
            command: Command string or argument list to execute.
            **kwargs: Additional keyword arguments passed to
                :class:`subprocess.Popen` (e.g. ``stderr=subprocess.PIPE``).
                ``stdin``, ``stdout``, and ``env`` are set automatically
                unless explicitly overridden.

        Returns:
            :class:`subprocess.Popen` with ``stdin`` and ``stdout`` pipes.

        Example::

            # Start an LSP server inside the sandbox
            proc = sb.popen(["pyright-langserver", "--stdio"])
            proc.stdin.write(b'...')  # send JSON-RPC request
            proc.stdin.flush()
            response = proc.stdout.readline()  # read response
            proc.terminate()
        """
        if isinstance(command, list):
            cmd_args = command
        else:
            cmd_args = ["bash", "-c", command]

        shell_pid = self._persistent_shell._process.pid

        if getattr(self, "_userns", False):
            # User namespace mode: use os.setns() in preexec_fn to enter
            # namespaces directly.  Avoids nsenter's setgroups() issue
            # (user namespaces require setgroups=deny, but nsenter calls it).
            _rootfs = str(self._rootfs)
            _wd = self._config.working_dir or "/"

            def _userns_preexec() -> None:
                # Enter user namespace first (grants all capabilities)
                with open(f"/proc/{shell_pid}/ns/user") as f:
                    os.setns(f.fileno(), 0)
                # Enter mount namespace (overlayfs visible here)
                with open(f"/proc/{shell_pid}/ns/mnt") as f:
                    os.setns(f.fileno(), 0)
                # Chroot + chdir into the sandbox
                os.chroot(_rootfs)
                os.chdir(_wd)

            defaults = {
                "stdin": subprocess.PIPE,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "env": self._cached_env,
            }
            defaults.update(kwargs)

            proc = subprocess.Popen(cmd_args, preexec_fn=_userns_preexec, **defaults)
        else:
            # Rootful mode: use nsenter into the sandbox's namespaces.
            # After pivot_root, the mount namespace root IS the rootfs,
            # so no chroot is needed — just enter the namespace.
            full_cmd = [
                "nsenter",
                f"--target={shell_pid}",
                "--pid",
                "--mount",
                "--root",
                "--wd=/",
                "--",
            ] + cmd_args

            defaults = {
                "stdin": subprocess.PIPE,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "env": self._cached_env,
            }
            defaults.update(kwargs)

            proc = subprocess.Popen(full_cmd, **defaults)

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
        """Read cgroup v2 Pressure Stall Information for this sandbox.

        Returns per-resource pressure as avg10/avg60/avg300 percentages::

            {
                "cpu":    {"avg10": 5.0, "avg60": 3.2, "avg300": 1.1},
                "memory": {"avg10": 0.0, "avg60": 0.0, "avg300": 0.0},
                "io":     {"avg10": 12.5, "avg60": 8.0, "avg300": 4.0},
            }

        Returns empty dict if cgroup v2 or PSI is not available.
        """
        cg = getattr(self, "_cgroup_path", None)
        if not cg:
            return {}
        result: dict[str, dict[str, float]] = {}
        for resource in ("cpu", "memory", "io"):
            psi_file = cg / f"{resource}.pressure"
            if not psi_file.exists():
                continue
            try:
                # Parse "some avg10=X avg60=Y avg300=Z total=T" line.
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
        """Hint the kernel to reclaim this sandbox's memory.

        Uses ``process_madvise(pidfd, MADV_COLD)`` to mark the sandbox
        process's memory as cold, so the kernel can swap it out when
        memory pressure rises.  The process keeps running — memory is
        paged back in transparently on next access.

        Useful in RL training: call on idle sandboxes while the GPU
        is busy with a training step, then resume normally.

        Returns True if the hint was accepted, False if unsupported.
        """
        shell = self._persistent_shell
        pidfd = getattr(shell, "_pidfd", None)
        if pidfd is None:
            return False

        import ctypes
        import ctypes.util
        import platform

        SYS_PROCESS_MADVISE = {"x86_64": 440, "aarch64": 440}.get(
            platform.machine()
        )
        MADV_COLD = 20

        if SYS_PROCESS_MADVISE is None:
            return False

        libc_name = ctypes.util.find_library("c")
        if not libc_name:
            return False
        libc = ctypes.CDLL(libc_name, use_errno=True)

        # process_madvise(pidfd, iovec, iovcnt, advice, flags)
        # We pass a zero-length iovec — the kernel applies the hint
        # to the entire process address space when iovec is empty.

        class Iovec(ctypes.Structure):
            _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]

        # Warn once if no swap is available.
        if not getattr(SandboxBase, "_swap_warned", False):
            try:
                with open("/proc/meminfo") as f:
                    for line in f:
                        if line.startswith("SwapTotal:"):
                            if int(line.split()[1]) == 0:
                                logger.warning(
                                    "reclaim_memory: no swap available, "
                                    "hint will have no effect. Enable swap "
                                    "or zram for memory reclamation to work."
                                )
                            SandboxBase._swap_warned = True
                            break
            except (OSError, ValueError):
                pass

        iov = Iovec(0, 0)
        ret = libc.syscall(SYS_PROCESS_MADVISE, pidfd, ctypes.byref(iov), 1, MADV_COLD, 0)
        return ret >= 0

    # -- Docker image export ----------------------------------------------- #

    def save_as_image(self, image_name: str) -> None:
        """Save current sandbox state as a Docker image.

        Tars the sandbox rootfs (base + all changes) and imports it via
        ``docker import``.  The resulting image can be used with both
        ``docker run`` and ``SandboxConfig(image=...)``.

        Args:
            image_name: Docker image name with optional tag
                (e.g. ``"my-app:cached"``).

        Example::

            sb = Sandbox(SandboxConfig(image="ubuntu:22.04"))
            sb.run("apt-get update && apt-get install -y python3")
            sb.save_as_image("my-app:with-python")

            # Later — fast start, no apt-get needed:
            sb2 = Sandbox(SandboxConfig(image="my-app:with-python"))
        """
        rootfs = self._rootfs
        if not rootfs or not rootfs.exists():
            raise RuntimeError("No rootfs available to export")

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
            raise RuntimeError(f"docker import failed: {stderr.strip()}")
        logger.info("Saved sandbox as Docker image: %s", image_name)

    # -- abstract methods -------------------------------------------------- #

    @abc.abstractmethod
    def reset(self) -> None:
        """Reset the sandbox filesystem to its initial state."""
        ...

    @abc.abstractmethod
    def delete(self) -> None:
        """Delete the sandbox and clean up all resources."""
        ...

    def fs_snapshot(self, path: str) -> None:
        """Save current filesystem state to a directory.

        Copies the overlayfs upper layer (all changes since creation/reset)
        to *path*.  Use :meth:`fs_restore` to return to this state later.
        Does not capture running process state — use
        :class:`~agentdocker_lite.CheckpointManager` for full process
        checkpoint/restore.

        Args:
            path: Directory to save the snapshot to (must not exist).
        """
        upper = getattr(self, "_upper_dir", None)
        if not upper or not upper.exists():
            raise RuntimeError("fs_snapshot() requires overlayfs (not available in this mode)")
        shutil.copytree(str(upper), path)
        logger.debug("FS snapshot saved: %s -> %s", upper, path)

    def fs_restore(self, path: str) -> None:
        """Restore filesystem state from a snapshot.

        Kills the persistent shell, replaces the overlayfs upper layer
        with the snapshot, and restarts the shell.  Running process state
        is lost — use :class:`~agentdocker_lite.CheckpointManager` for
        full process checkpoint/restore.

        Args:
            path: Directory containing a previous :meth:`fs_snapshot`.
        """
        upper = getattr(self, "_upper_dir", None)
        if not upper:
            raise RuntimeError("restore() requires overlayfs (not available in this mode)")
        if not Path(path).exists():
            raise FileNotFoundError(f"Snapshot not found: {path}")

        self._persistent_shell.kill()

        # Unmount overlayfs to flush kernel dentry cache (rootful only).
        # In userns mode, the setup script remounts fresh on shell restart.
        rootfs = getattr(self, "_rootfs", None)
        base_rootfs = getattr(self, "_base_rootfs", None)
        if not self._userns and rootfs:
            subprocess.run(["umount", str(rootfs)], capture_output=True)

        # Clear upper and replace with snapshot
        if self._userns:
            for child in upper.iterdir():
                try:
                    child.chmod(0o700)
                except OSError:
                    pass
        if upper.exists():
            shutil.rmtree(upper)
        shutil.copytree(path, str(upper))

        # Clear work dir
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

        # Remount overlayfs (rootful only).
        lowerdir_spec = getattr(self, "_lowerdir_spec", None) or base_rootfs
        if not self._userns and rootfs and lowerdir_spec and work:
            subprocess.run(
                [
                    "mount", "-t", "overlay", "overlay", "-o",
                    f"lowerdir={lowerdir_spec},"
                    f"upperdir={upper},"
                    f"workdir={work}",
                    str(rootfs),
                ],
                capture_output=True,
            )

        # Re-write seccomp helper for userns mode (upper dir was replaced).
        if self._config.seccomp and self._userns:
            from agentdocker_lite.security import build_seccomp_bpf
            bpf_bytes = build_seccomp_bpf()
            if bpf_bytes and upper:
                tmp_dir = upper / "tmp"
                tmp_dir.mkdir(parents=True, exist_ok=True)
                (tmp_dir / ".adl_seccomp.bpf").write_bytes(bpf_bytes)
                vendor_dir = Path(__file__).parent / "_vendor"
                helper_src = vendor_dir / "adl-seccomp"
                if helper_src.exists():
                    import shutil as _shutil
                    _shutil.copy2(str(helper_src), str(tmp_dir / ".adl_seccomp"))
                    (tmp_dir / ".adl_seccomp").chmod(0o755)

        self._persistent_shell.start()
        logger.debug("Snapshot restored: %s -> %s", path, upper)

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _host_path(self, container_path: str) -> Path:
        """Resolve container_path to host filesystem (for reads)."""
        return self._rootfs / container_path.lstrip("/")

    def _host_path_write(self, container_path: str) -> Path:
        """Resolve container_path to host filesystem (for writes).

        Overridden in RootfulSandbox/RootlessSandbox to write to the
        overlay upper dir in user namespace mode.
        """
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

    def __del__(self):
        try:
            if hasattr(self, "_persistent_shell"):
                self._persistent_shell.kill()
            if not getattr(self, "_userns", False):
                self._unmount_all()
        except Exception:
            pass

    def _unmount_all(self):
        """Default no-op; overridden in RootfulSandbox."""
        pass

    def __repr__(self) -> str:
        return f"Sandbox(name={self._name!r}, fs={self._fs_backend}, rootfs={self._rootfs})"

    # ------------------------------------------------------------------ #
    #  Stale sandbox cleanup                                               #
    # ------------------------------------------------------------------ #

    @staticmethod
    def cleanup_stale(env_base_dir: str = "/tmp/agentdocker_lite") -> int:
        """Clean up orphaned sandboxes left by crashed processes.

        Scans *env_base_dir* for sandbox directories, checks if the owner
        process is still alive (via the ``.pid`` file written at creation),
        and cleans up dead ones (unmount, remove cgroup, remove directory).

        Returns:
            Number of cleaned-up sandboxes.
        """
        base = Path(env_base_dir)
        if not base.exists():
            return 0

        cleaned = 0
        for entry in base.iterdir():
            if not entry.is_dir():
                continue

            pid_file = entry / ".pid"
            if not pid_file.exists():
                # No .pid file — likely not ours or very old; skip
                logger.debug("Skipping %s (no .pid file)", entry)
                continue

            try:
                pid = int(pid_file.read_text().strip())
            except (ValueError, OSError):
                logger.debug("Skipping %s (unreadable .pid file)", entry)
                continue

            # Check if process is alive.
            # Use pidfd to lock in process identity and avoid PID reuse races.
            from agentdocker_lite._pidfd import pidfd_open
            pidfd = pidfd_open(pid)
            if pidfd is not None:
                # pidfd_open succeeded → PID exists → owner still alive.
                alive = True
                os.close(pidfd)
            else:
                # pidfd_open failed → PID dead or unsupported.
                # Fallback to kill(0) for kernels without pidfd.
                try:
                    os.kill(pid, 0)
                    alive = True
                except ProcessLookupError:
                    alive = False
                except PermissionError:
                    alive = True

            if alive:
                logger.debug("Sandbox %s owner pid %d still alive, skipping", entry.name, pid)
                continue

            # Process is dead — clean up
            logger.info("Cleaning up stale sandbox %s (pid %d dead)", entry.name, pid)

            # Unmount everything under the rootfs
            rootfs_dir = entry / "rootfs"
            if rootfs_dir.exists():
                subprocess.run(
                    ["umount", "-R", "-l", str(rootfs_dir)],
                    capture_output=True,
                )

            # Remove cgroup
            cgroup_path = Path(f"/sys/fs/cgroup/agentdocker_lite/{entry.name}")
            if cgroup_path.exists():
                # Kill remaining processes in the cgroup
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

            # Remove directory
            shutil.rmtree(entry, ignore_errors=True)
            cleaned += 1

        if cleaned:
            logger.info("Cleaned up %d stale sandbox(es) under %s", cleaned, env_base_dir)
        return cleaned
