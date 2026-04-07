"""Persistent shell process for nitrobox sandboxes.

Spawns a shell inside a Linux namespace sandbox via Rust _core.spawn_sandbox(),
then communicates with it via stdin/stdout pipes and a signal fd protocol.
"""

from __future__ import annotations

import errno
import logging
import os
import select
import shlex
import threading
import time
from typing import TypedDict

from nitrobox._errors import SandboxInitError

logger = logging.getLogger(__name__)


# ======================================================================
# Typed dicts for the Rust FFI boundary
# ======================================================================

class SpawnConfig(TypedDict, total=False):
    """Config dict passed to ``_core.py_spawn_sandbox()``."""

    # Required
    rootfs: str
    shell: str
    working_dir: str
    env: dict[str, str]

    # Namespace
    rootful: bool
    userns: bool
    net_isolate: bool
    net_ns: str | None
    shared_userns: str | None
    subuid_range: tuple[int, int, int] | None

    # Filesystem
    lowerdir_spec: str | None
    upper_dir: str | None
    work_dir: str | None
    read_only: bool
    volumes: list[str]
    devices: list[str]
    shm_size: int | None
    tmpfs_mounts: list[str]

    # Security
    seccomp: bool
    cap_add: list[int]
    hostname: str | None
    landlock_read_paths: list[str]
    landlock_write_paths: list[str]
    landlock_ports: list[int]
    landlock_strict: bool

    # Process
    cgroup_path: str | None
    entrypoint: list[str]
    tty: bool

    # Network
    port_map: list[str]
    pasta_bin: str | None
    ipv6: bool

    # Internal
    env_dir: str | None


    # SpawnResult is a Rust pyclass (nitrobox._core.PySpawnResult)
    # with typed attributes: pid, stdin_fd, stdout_fd, signal_r_fd,
    # signal_w_fd_num, master_fd, pidfd.


class _PersistentShell:
    """Persistent shell inside a Linux namespace with chroot/pivot_root.

    Instead of ``fork -> exec chroot -> exec bash -> exec cmd`` per command
    (~330 ms each), this keeps a single long-lived bash process.  Commands
    are piped through stdin and output is collected via a separate signaling
    fd to avoid sentinel collision with command output.
    """

    def __init__(
        self,
        config: SpawnConfig,
        *,
        ulimits: dict[str, tuple[int, int]] | None = None,
    ):
        self._config = config
        self._ulimits = ulimits or {}

        # Process state (set by start())
        self.pid: int | None = None
        self._pidfd: int | None = None
        self._stdin_fd: int | None = None
        self._stdout_fd: int | None = None
        self._signal_r: int | None = None
        self._signal_fd: int | None = None  # signal_w fd num inside child
        self._master_fd: int | None = None
        self._err_r_fd: int | None = None
        self._lock = threading.Lock()

        self.start()

    # -- lifecycle --------------------------------------------------------- #

    def start(self) -> None:
        """Start (or restart) the persistent shell inside a new namespace."""
        if self.pid is not None and self.alive:
            self.kill()

        from nitrobox._core import py_spawn_sandbox
        result = py_spawn_sandbox(self._config)

        self.pid = result.pid
        self._stdin_fd = result.stdin_fd
        self._stdout_fd = result.stdout_fd
        self._signal_r = result.signal_r_fd
        self._signal_fd = result.signal_w_fd_num
        self._master_fd = result.master_fd
        self._pidfd = result.pidfd
        self._err_r_fd = result.err_r_fd

        if self._config.get("tty") and self._master_fd is not None:
            # In TTY mode, stdin and stdout go through master_fd
            self._stdin_fd = self._master_fd
            self._stdout_fd = self._master_fd

        # Build ulimit commands
        _ulimit_map = {
            "nofile": "-n", "nproc": "-u", "memlock": "-l",
            "stack": "-s", "core": "-c", "fsize": "-f",
            "data": "-d", "rss": "-m", "as": "-v",
        }
        ulimit_lines = ""
        for name, (soft, hard) in self._ulimits.items():
            flag = _ulimit_map.get(name)
            if flag:
                ulimit_lines += f"ulimit -H {flag} {hard} 2>/dev/null\n"
                ulimit_lines += f"ulimit -S {flag} {soft} 2>/dev/null\n"

        working_dir = self._config.get("working_dir", "/")

        # Send init script to shell (cd + signal ready)
        init_script = (
            "PS1='' PS2=''\n"
            + ulimit_lines
            + f"cd {shlex.quote(working_dir)} 2>/dev/null\n"
            f"echo 0 >&{self._signal_fd}\n"
        )
        self._write_input(init_script.encode())

        # Wait for the init signal
        ec_str = self._read_signal(timeout=30)
        if ec_str is None:
            # Diagnose: is the child dead or just unresponsive?
            detail = ""
            if self.pid is not None:
                try:
                    wpid, status = os.waitpid(self.pid, os.WNOHANG)
                    if wpid != 0:
                        code = os.waitstatus_to_exitcode(status)
                        detail += f" child exited with code {code}."
                        self.pid = None
                except ChildProcessError:
                    detail += " child already reaped."
                    self.pid = None

            # Read any warnings/errors from the init error pipe
            init_msgs = self._drain_err_pipe()
            if init_msgs:
                detail += f" init messages: {'; '.join(init_msgs)}"

            # Try to read any output the child produced (errors, etc.)
            if self._stdout_fd is not None:
                try:
                    import select as _sel
                    ep = _sel.epoll()
                    ep.register(self._stdout_fd, _sel.EPOLLIN)
                    events = ep.poll(0.1)
                    if events:
                        data = os.read(self._stdout_fd, 8192)
                        if data:
                            detail += f" output: {data.decode('utf-8', errors='replace').strip()!r}"
                    ep.close()
                except OSError:
                    pass

            rootfs = self._config.get("rootfs", "?")
            shell = self._config.get("shell", "?")
            raise SandboxInitError(
                f"Persistent shell failed to start "
                f"(rootfs={rootfs}, shell={shell}).{detail}"
            )

        # Shell started successfully — collect non-fatal init warnings.
        for warn_msg in self._drain_err_pipe():
            logger.warning("sandbox init: %s", warn_msg)

        rootful = self._config.get("rootful", False)
        ns_flags = "user,pid,mount" if not rootful else "pid,mount"
        if self._config.get("net_isolate"):
            ns_flags += ",net"
        logger.debug(
            "Persistent shell started: pid=%d rootfs=%s ns=[%s] tty=%s",
            self.pid, self._config.get("rootfs"), ns_flags,
            self._config.get("tty"),
        )

    def _drain_err_pipe(self) -> list[str]:
        """Non-blocking read of all data from the init error/warning pipe.

        Returns a list of decoded warning messages (``W:`` prefix stripped).
        Fatal messages (``F:`` prefix) are included as-is.
        Closes the pipe fd when done.
        """
        fd = self._err_r_fd
        if fd is None:
            return []
        msgs: list[str] = []
        try:
            import fcntl
            # Ensure non-blocking
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            chunks = []
            while True:
                try:
                    data = os.read(fd, 8192)
                    if not data:
                        break
                    chunks.append(data)
                except BlockingIOError:
                    break
                except OSError:
                    break
            if chunks:
                raw = b"".join(chunks).decode("utf-8", errors="replace")
                for line in raw.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("W:"):
                        msgs.append(line[2:])
                    elif line.startswith("F:"):
                        msgs.append(line[2:])
                    else:
                        msgs.append(line)
        except OSError:
            pass
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
            self._err_r_fd = None
        return msgs

    def kill(self) -> None:
        """Kill the shell and all processes in its PID namespace."""
        if self.pid is not None:
            try:
                import signal
                os.killpg(self.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                try:
                    os.kill(self.pid, 9)
                except (ProcessLookupError, PermissionError):
                    pass
            try:
                os.waitpid(self.pid, 0)
            except ChildProcessError:
                pass
            self.pid = None

        for fd_name in ("_master_fd", "_pidfd", "_signal_r", "_stdin_fd", "_stdout_fd", "_err_r_fd"):
            fd = getattr(self, fd_name, None)
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, fd_name, None)

    @property
    def alive(self) -> bool:
        if self.pid is None:
            return False
        try:
            pid, _ = os.waitpid(self.pid, os.WNOHANG)
            return pid == 0
        except ChildProcessError:
            return False

    # -- command execution ------------------------------------------------- #

    def execute(self, command: str, timeout: int | None = None) -> tuple[str, int]:
        """Execute *command* and return ``(output, exit_code)``."""
        with self._lock:
            if not self.alive:
                logger.warning("Persistent shell died, restarting")
                self.start()

            working_dir = self._config.get("working_dir", "/")
            shell = os.path.basename(self._config.get("shell", "bash"))
            script = (
                f"cd {shlex.quote(working_dir)} 2>/dev/null\n"
                f"{shell} -c {shlex.quote(command)} </dev/null 2>&1\n"
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
        """Write raw data to the shell's stdin (TTY mode only)."""
        if not self._config.get("tty"):
            raise RuntimeError("write_stdin() requires tty=True")
        if isinstance(data, str):
            data = data.encode()
        with self._lock:
            self._write_input(data)

    # -- internal I/O ------------------------------------------------------ #

    def _write_input(self, data: bytes) -> bool:
        """Write to the shell's stdin."""
        try:
            fd = self._stdin_fd
            if fd is None:
                return False
            os.write(fd, data)
        except (BrokenPipeError, OSError):
            return False
        return True

    @property
    def _stdout_read_fd(self) -> int | None:
        """File descriptor to read command output from."""
        return self._stdout_fd

    def _read_signal(self, timeout: float | None = None) -> str | None:
        """Read a single line from the signal fd."""
        if self._signal_r is None:
            return None
        ep = select.epoll()
        ep.register(self._signal_r, select.EPOLLIN)
        try:
            events = ep.poll(timeout if timeout is not None else -1, maxevents=1)
            if not events:
                return None
            data = os.read(self._signal_r, 256)
            if not data:
                return None
            return data.decode("utf-8", errors="replace").strip()
        except OSError:
            return None
        finally:
            ep.close()

    def _read_until_signal(
        self, timeout: float | None = None
    ) -> tuple[str | None, int]:
        """Read stdout until the signal fd fires with the exit code."""
        deadline = time.monotonic() + timeout if timeout else None
        stdout_fd = self._stdout_read_fd
        assert stdout_fd is not None, "stdout fd not set"
        signal_fd = self._signal_r
        buf = b""
        parts: list[str] = []
        exit_code: int | None = None

        ep = select.epoll()
        ep.register(stdout_fd, select.EPOLLIN)
        if signal_fd is not None:
            ep.register(signal_fd, select.EPOLLIN)

        try:
            while True:
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return None, -2
                    wait = min(remaining, 2.0)
                else:
                    wait = 5.0

                events = ep.poll(wait)
                ready_fds = {fd for fd, _ in events}

                # No events and process died → shell is gone.
                if not events and not self.alive:
                    if buf:
                        parts.append(buf.decode("utf-8", errors="backslashreplace"))
                    return None, -1

                # Read stdout data if available.
                if stdout_fd in ready_fds:
                    try:
                        chunk = os.read(stdout_fd, 65536)
                    except OSError as e:
                        if e.errno == errno.EIO:
                            break
                        return None, -1
                    if not chunk:
                        return None, -1
                    buf += chunk

                    while b"\n" in buf:
                        line_bytes, buf = buf.split(b"\n", 1)
                        line_str = line_bytes.decode("utf-8", errors="backslashreplace")
                        parts.append(line_str + "\n")

                # Check signal fd for exit code.
                if signal_fd is not None and signal_fd in ready_fds:
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
                    while True:
                        if not ep.poll(0.01):
                            break
                        try:
                            chunk = os.read(stdout_fd, 65536)
                        except OSError:
                            break
                        if not chunk:
                            break
                        buf += chunk

                    if buf:
                        parts.append(buf.decode("utf-8", errors="backslashreplace"))

                    return "".join(parts), exit_code
        finally:
            ep.close()

        # Reached via break (e.g. PTY EIO)
        if buf:
            parts.append(buf.decode("utf-8", errors="backslashreplace"))
        return "".join(parts) if parts else None, exit_code if exit_code is not None else -1
