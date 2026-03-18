"""Persistent shell process for agentdocker-lite sandboxes."""

from __future__ import annotations

import errno
import logging
import os
import pty as pty_mod
import select
import shlex
import subprocess
import termios
import threading
import time
from typing import Optional

logger = logging.getLogger(__name__)

# Docker-default security paths (applied inside the namespace).
_DEFAULT_MASKED_PATHS = [
    "/proc/kcore", "/proc/keys", "/proc/timer_list",
    "/proc/sched_debug", "/sys/firmware", "/proc/scsi",
]
_DEFAULT_READONLY_PATHS = [
    "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys",
    "/proc/sysrq-trigger",
]


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
        rootfs,
        shell: str,
        env: dict[str, str],
        working_dir: str = "/",
        cgroup_path=None,
        tty: bool = False,
        net_isolate: bool = False,
        seccomp: bool = True,
        landlock_read: Optional[list[str]] = None,
        landlock_write: Optional[list[str]] = None,
        landlock_tcp_ports: Optional[list[int]] = None,
        userns_setup_script: Optional[str] = None,
        systemd_scope_properties: Optional[list[str]] = None,
        hostname: Optional[str] = None,
    ):
        self._rootfs = rootfs
        self._shell = shell
        self._env = env
        self._working_dir = working_dir
        self._cgroup_path = cgroup_path
        self._tty = tty
        self._net_isolate = net_isolate
        self._seccomp = seccomp
        self._landlock_read = landlock_read
        self._landlock_write = landlock_write
        self._landlock_tcp_ports = landlock_tcp_ports
        self._userns = userns_setup_script is not None
        self._userns_setup_script = userns_setup_script
        self._systemd_scope_properties = systemd_scope_properties
        self._hostname = hostname
        self._process: Optional[subprocess.Popen] = None
        self._pidfd: Optional[int] = None
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

        if self._userns:
            # User namespace mode: setup script handles mount/chroot,
            # stdin is used for phase 2 init (post-chroot).
            unshare_cmd: list[str] = [
                "unshare", "--user", "--map-root-user",
                "--pid", "--mount", "--uts", "--ipc",
            ]
            if self._net_isolate:
                unshare_cmd.append("--net")
            unshare_cmd.extend(["--fork", "bash", str(self._userns_setup_script)])

            # Wrap in systemd-run --user --scope for cgroup delegation
            if self._systemd_scope_properties:
                cmd: list[str] = ["systemd-run", "--user", "--scope", "--quiet"]
                for prop in self._systemd_scope_properties:
                    cmd.extend(["--property", prop])
                cmd.append("--")
                cmd.extend(unshare_cmd)
            else:
                cmd = unshare_cmd
        else:
            # Rootful mode: pivot_root into rootfs (CRIU-compatible).
            # pivot_root changes the mount namespace root, unlike chroot
            # which only changes the process root.  CRIU requires these
            # to match for checkpoint/restore to work.
            cmd = ["unshare", "--pid", "--mount", "--uts", "--ipc"]
            # Time namespace for CRIU monotonic clock continuity.
            self._timens = os.path.exists("/proc/self/ns/time")
            if self._timens:
                cmd.append("--time")
            if self._net_isolate:
                cmd.append("--net")
            shell_exec = self._shell
            if "bash" in self._shell:
                shell_exec += " --norc --noprofile"
            # pivot_root makes root == mntns root (CRIU-compatible).
            # We cannot unmount old root from the script because the
            # rootfs may lack mount/umount and host tools fail due to
            # glibc version mismatch.  The old root is cleaned up via
            # _cleanup_pivot_old() using ctypes syscalls after start.
            pivot_script = (
                "mount --make-rprivate / && "
                f"cd {shlex.quote(str(self._rootfs))} && "
                "mkdir -p .pivot_old && "
                "pivot_root . .pivot_old && "
                "cd / && "
                # setsid makes the shell a session leader within its
                # PID namespace (required for CRIU checkpoint).
                f"exec setsid {shell_exec}"
            )
            cmd.extend(["--fork", "bash", "-c", pivot_script])

        # Build preexec_fn
        _cg_path = self._cgroup_path

        if self._userns:
            # User namespace: no cgroup, no landlock in preexec.
            def _preexec() -> None:
                pass
        else:
            # Rootful: cgroup in preexec. seccomp applied via init script
            # AFTER mount /proc + /dev (which need mount syscall to work first).
            def _preexec() -> None:
                if _cg_path:
                    try:
                        with open(_cg_path / "cgroup.procs", "w") as f:
                            f.write(str(os.getpid()))
                    except Exception:
                        pass

        preexec_fn = _preexec

        # When systemd-run wraps the command, it needs host env
        # (DBUS_SESSION_BUS_ADDRESS etc.) to talk to the user's systemd.
        # The sandbox env is applied inside the chroot via the init_script.
        popen_env = None if self._systemd_scope_properties else self._env

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
                env=popen_env,
                bufsize=0,
                preexec_fn=preexec_fn,
                pass_fds=(signal_w,),
                start_new_session=True,
            )
            os.close(slave_fd)
            self._master_fd = master_fd
        else:
            self._process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=popen_env,
                bufsize=0,
                preexec_fn=preexec_fn,
                pass_fds=(signal_w,),
                start_new_session=True,
            )

        # Close write end in parent -- only the child should write to it.
        os.close(signal_w)
        self._signal_w = None

        # Initialize shell: disable prompts, cd to working dir, signal ready.
        # In userns mode, /proc and /dev are already set up by the setup script
        # before chroot.  In rootful mode, they're set up here (inside chroot).
        # Security hardening: mask sensitive paths and make others read-only.
        # Uses Docker-default lists. Applied after /proc and /dev are mounted.
        _mask_snippet = ""
        for p in _DEFAULT_MASKED_PATHS:
            _mask_snippet += (
                f"if [ -d {p} ]; then mount -t tmpfs tmpfs {p} 2>/dev/null; "
                f"elif [ -e {p} ]; then mount --bind /dev/null {p} 2>/dev/null; fi\n"
            )
        _ro_snippet = ""
        for p in _DEFAULT_READONLY_PATHS:
            _ro_snippet += (
                f"mount --bind {p} {p} 2>/dev/null && "
                f"mount -o remount,ro,bind {p} 2>/dev/null\n"
            )

        _seccomp_snippet = (
            "for py in python3 python3.13 python3.12 python3.11 python3.10 python; do\n"
            "  if command -v $py >/dev/null 2>&1; then\n"
            "    $py /tmp/.adl_seccomp.py 2>/dev/null && break\n"
            "  fi\n"
            "done\n"
            if self._seccomp else ""
        )
        _hostname_snippet = (
            f"hostname {shlex.quote(self._hostname)} 2>/dev/null\n"
            if self._hostname else ""
        )

        if self._userns:
            # User namespace: setup script already did mount/dev/chroot.
            # This runs inside the chroot bash (read from stdin pipe).
            init_script = (
                "PS1='' PS2=''\n"
                + _mask_snippet
                + _ro_snippet
                + _hostname_snippet
                + _seccomp_snippet
                + f"cd {shlex.quote(self._working_dir)} 2>/dev/null\n"
                f"echo 0 >&{self._signal_fd}\n"
            )
        else:
            init_script = (
                "PS1='' PS2=''\n"
                # Mount /proc (needed for $ORIGIN RPATH, /proc/self/fd, ps, etc.)
                "mount -t proc proc /proc 2>/dev/null\n"
                # Populate /dev with essential device nodes and symlinks.
                # Docker export leaves /dev nearly empty (regular files, not devices).
                # NOTE: /dev/null must be created FIRST — later 2>/dev/null redirects
                # would otherwise create it as a regular file on the fresh tmpfs.
                "mount -t tmpfs -o nosuid,mode=0755 tmpfs /dev 2>/proc/self/fd/1\n"
                "mknod -m 666 /dev/null c 1 3\n"
                "mknod -m 666 /dev/zero c 1 5 2>/dev/null\n"
                "mknod -m 666 /dev/full c 1 7 2>/dev/null\n"
                "mknod -m 444 /dev/random c 1 8 2>/dev/null\n"
                "mknod -m 444 /dev/urandom c 1 9 2>/dev/null\n"
                "mknod -m 666 /dev/tty c 5 0 2>/dev/null\n"
                "ln -sf /proc/self/fd /dev/fd 2>/dev/null\n"
                "ln -sf /proc/self/fd/0 /dev/stdin 2>/dev/null\n"
                "ln -sf /proc/self/fd/1 /dev/stdout 2>/dev/null\n"
                "ln -sf /proc/self/fd/2 /dev/stderr 2>/dev/null\n"
                "mkdir -p /dev/pts /dev/shm 2>/dev/null\n"
                + _mask_snippet
                + _ro_snippet
                + _hostname_snippet
                + _seccomp_snippet
                + f"cd {shlex.quote(self._working_dir)} 2>/dev/null\n"
                f"echo 0 >&{self._signal_fd}\n"
            )
        self._write_input(init_script.encode())

        # Wait for the init signal.
        ec_str = self._read_signal(timeout=30)
        if ec_str is None:
            raise RuntimeError(
                f"Persistent shell failed to start within 30 s "
                f"(rootfs={self._rootfs}, shell={self._shell})"
            )

        # Create pidfd for race-free process management.
        from agentdocker_lite._pidfd import pidfd_open
        self._pidfd = pidfd_open(self._process.pid)

        # Clean up old root mounts left by pivot_root (rootful mode only).
        if not self._userns:
            self._cleanup_pivot_old()

        ns_flags = "user,pid,mount" if self._userns else "pid,mount"
        if self._net_isolate:
            ns_flags += ",net"
        logger.debug(
            "Persistent shell started: pid=%d rootfs=%s ns=[%s] tty=%s",
            self._process.pid,
            self._rootfs,
            ns_flags,
            self._tty,
        )

    def _cleanup_pivot_old(self) -> None:
        """Unmount /.pivot_old inside the shell's mount namespace.

        After pivot_root, the old host root and all its submounts remain
        visible at /.pivot_old.  We clean them up via the umount2 syscall
        (MNT_DETACH) from a forked child that enters the mount namespace.
        This avoids needing mount/umount binaries in the rootfs.
        """
        if self._process is None:
            return

        # Find the init process (PID 1 inside the namespace).
        pid = self._process.pid
        children_file = f"/proc/{pid}/task/{pid}/children"
        try:
            children = open(children_file).read().strip().split()
            init_pid = int(children[0]) if children else pid
        except (OSError, ValueError):
            init_pid = pid

        mnt_ns = f"/proc/{init_pid}/ns/mnt"
        root_path = f"/proc/{init_pid}/root"
        if not os.path.exists(mnt_ns):
            return

        import ctypes
        import ctypes.util

        MNT_DETACH = 2
        CLONE_NEWNS = 0x00020000

        libc_name = ctypes.util.find_library("c")
        if not libc_name:
            return
        libc = ctypes.CDLL(libc_name, use_errno=True)

        child_pid = os.fork()
        if child_pid == 0:
            # Child: enter mount namespace, chroot to target root,
            # then unmount the old host root.
            try:
                mnt_fd = os.open(mnt_ns, os.O_RDONLY)
                root_fd = os.open(root_path, os.O_RDONLY | os.O_DIRECTORY)
                libc.setns(mnt_fd, CLONE_NEWNS)
                os.close(mnt_fd)
                # Align our root with the mount namespace root.
                os.fchdir(root_fd)
                os.chroot(".")
                os.close(root_fd)
                os.chdir("/")
                libc.umount2(b"/.pivot_old", MNT_DETACH)
            except Exception:
                pass
            finally:
                os._exit(0)
        else:
            os.waitpid(child_pid, 0)

    def kill(self) -> None:
        """Kill the shell and all processes in its PID namespace."""
        if self._process is not None:
            try:
                # Kill the entire process group (unshare + forked children).
                # start_new_session=True makes the process a session leader,
                # so its PID == PGID.
                import signal
                os.killpg(self._process.pid, signal.SIGKILL)
                self._process.wait(timeout=5)
            except Exception:
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
        if self._pidfd is not None:
            try:
                os.close(self._pidfd)
            except OSError:
                pass
            self._pidfd = None
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
