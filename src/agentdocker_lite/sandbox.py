"""Linux namespace sandbox with overlayfs or btrfs filesystem backend.

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

import errno
import logging
import os
import pty as pty_mod
import select
import shlex
import shutil
import subprocess
import termios
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ====================================================================== #
#  Configuration                                                          #
# ====================================================================== #


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
        cpu_max: cgroup v2 ``cpu.max`` value (e.g. ``"50000 100000"``).
        memory_max: cgroup v2 ``memory.max`` value in bytes.
        pids_max: cgroup v2 ``pids.max`` value.
        tty: Use a pseudo-terminal instead of pipes for command I/O.
            Enables ``write_stdin()`` for interactive programs.  Default
            ``False`` preserves the fast pipe-based path.
        net_isolate: Create a separate network namespace (loopback only).
            Default ``False`` inherits the host network.
    """

    image: str = ""
    working_dir: str = "/"
    environment: dict[str, str] = field(default_factory=dict)
    volumes: list[str] = field(default_factory=list)
    fs_backend: str = "overlayfs"
    env_base_dir: str = "/tmp/agentdocker_lite"
    rootfs_cache_dir: str = "/tmp/agentdocker_lite_rootfs_cache"
    cpu_max: Optional[str] = None
    memory_max: Optional[str] = None
    pids_max: Optional[str] = None
    tty: bool = False
    net_isolate: bool = False


# ====================================================================== #
#  Persistent shell                                                       #
# ====================================================================== #


class _PersistentShell:
    """Persistent shell process inside a Linux namespace with chroot.

    Instead of ``fork -> exec chroot -> exec bash -> exec cmd`` per command
    (~330 ms each), this keeps a single long-lived bash process.  Commands
    are piped through stdin and output is collected via a separate signaling
    fd to avoid sentinel collision with command output.

    Namespace flags (via ``unshare``):

    * ``--pid``   -- PID namespace
    * ``--mount`` -- mount namespace
    * ``--fork``  -- child becomes PID 1 in the new PID namespace
    """

    def __init__(
        self,
        rootfs: Path,
        shell: str,
        env: dict[str, str],
        working_dir: str = "/",
        cgroup_path: Optional[Path] = None,
        tty: bool = False,
        net_isolate: bool = False,
    ):
        self._rootfs = rootfs
        self._shell = shell
        self._env = env
        self._working_dir = working_dir
        self._cgroup_path = cgroup_path
        self._tty = tty
        self._net_isolate = net_isolate
        self._process: Optional[subprocess.Popen] = None
        self._master_fd: Optional[int] = None
        self._lock = threading.Lock()
        self._signal_r: Optional[int] = None
        self._signal_w: Optional[int] = None
        self.start()

    # -- lifecycle --------------------------------------------------------- #

    def start(self) -> None:
        """Start (or restart) the persistent shell inside a new namespace."""
        if self._process and self._process.poll() is None:
            self.kill()

        # Create signal pipe for command completion signaling.
        # The child writes its exit code to signal_w; we read from signal_r.
        signal_r, signal_w = os.pipe()
        self._signal_r = signal_r
        self._signal_fd = signal_w  # Remember fd number for bash scripts

        cmd: list[str] = ["unshare", "--pid", "--mount"]
        if self._net_isolate:
            cmd.append("--net")
        cmd.extend(["--fork", "chroot", str(self._rootfs), self._shell])
        if "bash" in self._shell:
            cmd.extend(["--norc", "--noprofile"])

        preexec_fn = None
        if self._cgroup_path:
            cg_procs = self._cgroup_path / "cgroup.procs"

            def _add_to_cgroup() -> None:
                try:
                    with open(cg_procs, "w") as f:
                        f.write(str(os.getpid()))
                except Exception:
                    pass

            preexec_fn = _add_to_cgroup

        if self._tty:
            master_fd, slave_fd = pty_mod.openpty()
            # Disable echo so input doesn't pollute output.
            attrs = termios.tcgetattr(master_fd)
            attrs[3] &= ~termios.ECHO  # lflags
            termios.tcsetattr(master_fd, termios.TCSANOW, attrs)

            self._process = subprocess.Popen(
                cmd,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                env=self._env,
                bufsize=0,
                preexec_fn=preexec_fn,
                pass_fds=(signal_w,),
            )
            os.close(slave_fd)
            self._master_fd = master_fd
        else:
            self._process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=self._env,
                bufsize=0,
                preexec_fn=preexec_fn,
                pass_fds=(signal_w,),
            )

        # Close write end in parent -- only the child should write to it.
        os.close(signal_w)
        self._signal_w = None

        # Initialize shell: disable prompts, cd to working dir, signal ready.
        init_script = (
            "PS1='' PS2=''\n"
            f"cd {shlex.quote(self._working_dir)} 2>/dev/null\n"
            f"echo 0 >&{self._signal_fd}\n"
        )
        self._write_input(init_script.encode())

        # Wait for the init signal.
        ec_str = self._read_signal(timeout=10)
        if ec_str is None:
            raise RuntimeError(
                f"Persistent shell failed to start within 10 s "
                f"(rootfs={self._rootfs}, shell={self._shell})"
            )

        ns_flags = "pid,mount" + (",net" if self._net_isolate else "")
        logger.debug(
            "Persistent shell started: pid=%d rootfs=%s ns=[%s] tty=%s",
            self._process.pid,
            self._rootfs,
            ns_flags,
            self._tty,
        )

    def kill(self) -> None:
        """Kill the shell and all processes in its PID namespace."""
        if self._process is not None:
            try:
                self._process.kill()
                self._process.wait(timeout=5)
            except Exception:
                pass
            self._process = None
        if self._master_fd is not None:
            try:
                os.close(self._master_fd)
            except OSError:
                pass
            self._master_fd = None
        if self._signal_r is not None:
            try:
                os.close(self._signal_r)
            except OSError:
                pass
            self._signal_r = None

    @property
    def alive(self) -> bool:
        return self._process is not None and self._process.poll() is None

    # -- command execution ------------------------------------------------- #

    def execute(self, command: str, timeout: Optional[int] = None) -> tuple[str, int]:
        """Execute *command* and return ``(output, exit_code)``.

        Each command runs inside a ``bash -c`` sub-shell so it cannot
        alter the persistent shell's own state.  Stdin is redirected
        from ``/dev/null`` to prevent commands from consuming the
        control pipe.

        Completion is signaled via the signal pipe fd, so command
        output can never collide with the control protocol.
        """
        with self._lock:
            if not self.alive:
                logger.warning("Persistent shell died, restarting")
                self.start()

            # Protocol:
            #   1. cd to working_dir
            #   2. run command in isolated sub-shell, stdin=/dev/null
            #   3. write exit code to signal pipe fd
            script = (
                f"cd {shlex.quote(self._working_dir)} 2>/dev/null\n"
                f"bash -c {shlex.quote(command)} </dev/null 2>&1\n"
                f"echo $? >&{self._signal_fd}\n"
            )

            if not self._write_input(script.encode()):
                return "Shell pipe broken", -1

            output, exit_code = self._read_until_signal(timeout=timeout)

            if output is None:
                if exit_code == -2:
                    self.kill()
                    self.start()
                    return (
                        f"Command timed out after {timeout} seconds",
                        124,
                    )
                return "Shell terminated unexpectedly", -1

            return output, exit_code

    def write_stdin(self, data: str | bytes) -> None:
        """Write raw data to the shell's stdin.

        Only works in PTY mode (``tty=True``).  Use this to send input
        to interactive programs running inside the sandbox.
        """
        if not self._tty:
            raise RuntimeError("write_stdin() requires tty=True")
        if isinstance(data, str):
            data = data.encode()
        with self._lock:
            self._write_input(data)

    # -- internal I/O ------------------------------------------------------ #

    def _write_input(self, data: bytes) -> bool:
        """Write to the shell's stdin (PTY master or pipe)."""
        try:
            if self._tty and self._master_fd is not None:
                os.write(self._master_fd, data)
            elif self._process and self._process.stdin:
                self._process.stdin.write(data)
                self._process.stdin.flush()
            else:
                return False
        except (BrokenPipeError, OSError):
            return False
        return True

    @property
    def _stdout_fd(self) -> int:
        """File descriptor to read command output from."""
        if self._tty and self._master_fd is not None:
            return self._master_fd
        return self._process.stdout.fileno()

    def _read_signal(self, timeout: Optional[float] = None) -> Optional[str]:
        """Read a single line from the signal fd."""
        if self._signal_r is None:
            return None
        ready, _, _ = select.select([self._signal_r], [], [], timeout)
        if not ready:
            return None
        try:
            data = os.read(self._signal_r, 256)
            if not data:
                return None
            return data.decode("utf-8", errors="replace").strip()
        except OSError:
            return None

    def _read_until_signal(
        self, timeout: Optional[float] = None
    ) -> tuple[Optional[str], int]:
        """Read stdout until the signal fd fires with the exit code.

        Returns:
            ``(output, exit_code)`` on success.
            ``(None, -1)`` if the shell died.
            ``(None, -2)`` on timeout.
        """
        deadline = time.monotonic() + timeout if timeout else None
        stdout_fd = self._stdout_fd
        signal_fd = self._signal_r
        buf = b""
        parts: list[str] = []
        exit_code: Optional[int] = None

        while True:
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None, -2
                wait = min(remaining, 2.0)
            else:
                wait = 5.0

            fds_to_watch = [stdout_fd]
            if signal_fd is not None:
                fds_to_watch.append(signal_fd)

            ready, _, _ = select.select(fds_to_watch, [], [], wait)

            # Read stdout data if available.
            if stdout_fd in ready:
                try:
                    chunk = os.read(stdout_fd, 65536)
                except OSError as e:
                    # PTY raises EIO when slave side closes — not an error,
                    # just means the child is gone.
                    if e.errno == errno.EIO:
                        break
                    return None, -1
                if not chunk:
                    return None, -1
                buf += chunk

                # Decode complete lines from buffer.
                while b"\n" in buf:
                    line_bytes, buf = buf.split(b"\n", 1)
                    line_str = line_bytes.decode("utf-8", errors="backslashreplace")
                    parts.append(line_str + "\n")

            # Check signal fd for exit code.
            if signal_fd is not None and signal_fd in ready:
                try:
                    sig_data = os.read(signal_fd, 256)
                except OSError:
                    return None, -1
                if sig_data:
                    try:
                        exit_code = int(
                            sig_data.decode("utf-8", errors="replace").strip()
                        )
                    except ValueError:
                        exit_code = -1

            # If we got the exit code, drain any remaining stdout.
            if exit_code is not None:
                # Non-blocking drain of remaining stdout.
                while True:
                    drain_ready, _, _ = select.select([stdout_fd], [], [], 0.01)
                    if not drain_ready:
                        break
                    try:
                        chunk = os.read(stdout_fd, 65536)
                    except OSError:
                        break  # EIO from PTY or pipe closed
                    if not chunk:
                        break
                    buf += chunk

                # Decode remaining buffer.
                if buf:
                    parts.append(buf.decode("utf-8", errors="backslashreplace"))

                return "".join(parts), exit_code

            if not ready and self._process.poll() is not None:
                if buf:
                    parts.append(buf.decode("utf-8", errors="backslashreplace"))
                return None, -1

        # Reached via break (e.g. PTY EIO) — return whatever we have.
        if buf:
            parts.append(buf.decode("utf-8", errors="backslashreplace"))
        return "".join(parts) if parts else None, exit_code if exit_code is not None else -1


# ====================================================================== #
#  Sandbox                                                                #
# ====================================================================== #


class Sandbox:
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
        if not config.image:
            raise ValueError("SandboxConfig.image is required.")

        self._config = config
        self._name = name
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
        )
        shell_ms = (time.monotonic() - t3) * 1000

        self._bg_handles: dict[str, str] = {}  # handle -> pid

        logger.info(
            "Sandbox ready: name=%s rootfs=%s fs=%s "
            "[setup: fs=%.1fms cgroup=%.1fms volumes=%.1fms shell=%.1fms]",
            name,
            self._rootfs,
            self._fs_backend,
            fs_ms,
            cg_ms,
            vol_ms,
            shell_ms,
        )

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
        shell_pid = self._persistent_shell._process.pid

        if isinstance(command, list):
            cmd_args = command
        else:
            cmd_args = ["bash", "-c", command]

        full_cmd = [
            "nsenter",
            f"--target={shell_pid}",
            "--pid",
            "--mount",
            "--",
            "chroot", str(self._rootfs),
        ] + cmd_args

        defaults = {
            "stdin": subprocess.PIPE,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "env": self._cached_env,
        }
        defaults.update(kwargs)

        proc = subprocess.Popen(full_cmd, **defaults)
        logger.debug(
            "popen pid=%d in sandbox ns (shell_pid=%d): %s",
            proc.pid, shell_pid, cmd_args,
        )
        return proc

    # -- reset / delete ---------------------------------------------------- #

    def reset(self) -> None:
        """Reset the sandbox filesystem to its initial state.

        This is the RL fast-path: ~27ms for overlayfs, ~28ms for btrfs.
        """
        self._bg_handles.clear()
        t0 = time.monotonic()

        self._persistent_shell.kill()
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

        elapsed_ms = (time.monotonic() - t0) * 1000
        logger.debug(
            "Environment reset (%.3fms fs=%s): %s",
            elapsed_ms,
            self._fs_backend,
            self._env_dir,
        )

    def delete(self) -> None:
        """Delete the sandbox and clean up all resources."""
        t0 = time.monotonic()

        self._persistent_shell.kill()
        self._unmount_all()

        if self._fs_backend == "btrfs" and self._btrfs_active:
            subprocess.run(
                ["btrfs", "subvolume", "delete", str(self._rootfs)],
                capture_output=True,
            )
            self._btrfs_active = False

        self._cleanup_cgroup()

        if self._env_dir.exists():
            shutil.rmtree(self._env_dir, ignore_errors=True)

        elapsed_ms = (time.monotonic() - t0) * 1000
        logger.info(
            "Deleted sandbox (%.1fms fs=%s): %s",
            elapsed_ms,
            self._fs_backend,
            self._env_dir,
        )

    # -- file operations --------------------------------------------------- #

    def copy_to(self, local_path: str, container_path: str) -> None:
        """Copy a file from host into the sandbox."""
        host_dst = self._host_path(container_path)
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
        host_path = self._host_path(container_path)
        host_path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            host_path.write_bytes(content)
        else:
            host_path.write_text(content)

    @property
    def rootfs(self) -> Path:
        """Path to the sandbox's rootfs on the host."""
        return self._rootfs

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
                Sandbox._verify_btrfs_subvolume(cached_rootfs)
            return cached_rootfs

        lock_path = rootfs_cache_dir / f".{safe_name}.lock"
        rootfs_cache_dir.mkdir(parents=True, exist_ok=True)
        with open(lock_path, "w") as lock_fd:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            try:
                if cached_rootfs.exists() and cached_rootfs.is_dir():
                    logger.info("Rootfs prepared by another worker: %s", cached_rootfs)
                    if fs_backend == "btrfs":
                        Sandbox._verify_btrfs_subvolume(cached_rootfs)
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
        import shutil

        for mount_point in reversed(self._bind_mounts):
            subprocess.run(["umount", "-l", str(mount_point)], capture_output=True)
        self._bind_mounts.clear()
        for tmpdir in self._cow_tmpdirs:
            shutil.rmtree(tmpdir, ignore_errors=True)
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
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _host_path(self, container_path: str) -> Path:
        return self._rootfs / container_path.lstrip("/")

    def _detect_shell(self) -> str:
        if self._host_path("/bin/bash").exists():
            return "/bin/bash"
        return "/bin/sh"

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
            self._unmount_all()
        except Exception:
            pass

    def __repr__(self) -> str:
        return f"Sandbox(name={self._name!r}, fs={self._fs_backend}, rootfs={self._rootfs})"
