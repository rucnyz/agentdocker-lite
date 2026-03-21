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

# Docker-default masked/readonly paths are hardcoded in the adl-seccomp
# static binary (_vendor/adl-seccomp.c) which applies them before exec.


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
        read_only: bool = False,
        subuid_range: Optional[tuple[int, int, int]] = None,
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
        self._read_only = read_only
        self._subuid_range = subuid_range  # (outer_id, sub_start, sub_count) or None
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
            use_full_mapping = self._subuid_range is not None

            unshare_cmd: list[str] = [
                "unshare", "--user",
            ]
            if not use_full_mapping:
                # Fallback: only map current uid → root (no apt-get, useradd, etc.)
                unshare_cmd.append("--map-root-user")

            unshare_cmd.extend([
                "--pid", "--mount", "--propagation", "slave",
                "--uts", "--ipc",
            ])
            if self._net_isolate:
                unshare_cmd.append("--net")

            if use_full_mapping:
                # With full uid mapping, we need synchronization:
                # 1. Child starts in new user namespace (no mapping yet)
                # 2. Child blocks on a sync pipe
                # 3. Parent calls newuidmap/newgidmap to set full mapping
                # 4. Parent signals child by closing the pipe
                # 5. Child continues with setup script (mount, chroot, etc.)
                sync_r, sync_w = os.pipe()
                wrapper = (
                    f"exec 3<&{sync_r}; exec {sync_r}<&-; "
                    f"read -n1 <&3; exec 3<&-; "
                    f"exec bash {shlex.quote(str(self._userns_setup_script))}"
                )
                unshare_cmd.extend(["--fork", "bash", "-c", wrapper])
                self._sync_fds = (sync_r, sync_w)
            else:
                unshare_cmd.extend(["--fork", "bash", str(self._userns_setup_script)])
                self._sync_fds = None

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
            cmd = ["unshare", "--pid", "--mount", "--propagation", "slave",
                   "--uts", "--ipc"]
            # Time namespace for CRIU monotonic clock continuity.
            self._timens = os.path.exists("/proc/self/ns/time")
            if self._timens:
                cmd.append("--time")
            if self._net_isolate:
                cmd.append("--net")
            shell_exec = self._shell
            if "bash" in self._shell:
                shell_exec += " --norc --noprofile"

            # Write seccomp BPF + static helper into rootfs BEFORE pivot_root.
            if self._seccomp:
                self._prepare_seccomp_helper()

            # adl-seccomp (static binary) runs AFTER pivot_root and handles:
            # mount /proc + /dev, cap drop, mask paths, readonly, seccomp, exec shell.
            # All done inside the new root — no host tools or glibc needed.
            rootfs_q = shlex.quote(str(self._rootfs))

            # hostname must be set before seccomp (blocks sethostname).
            # Try /proc write first (no binary needed), fall back to hostname cmd.
            hostname_cmd = ""
            if self._hostname:
                hn = shlex.quote(self._hostname)
                hostname_cmd = f"echo {hn} > /proc/sys/kernel/hostname 2>/dev/null || hostname {hn} 2>/dev/null; "

            seccomp_wrap = "/tmp/.adl_seccomp " if self._seccomp else ""

            # Mount isolation (defense in depth — runc approach):
            # 1. mount --make-rslave / : allows host->child propagation
            #    but blocks child->host propagation.  Safer than rprivate
            #    which can race with concurrent mount events.
            #    (see runc prepareRoot: MS_SLAVE|MS_REC)
            # 2. mount --bind rootfs rootfs : self-bind creates a new
            #    mount point with controllable propagation, independent
            #    of the parent mount's shared subtrees.  Also ensures
            #    rootfs is a mount point (required by pivot_root).
            # 3. mount --make-private rootfs : ensure the rootfs mount
            #    itself cannot propagate in either direction.
            # 4. After pivot_root, /.pivot_old cleanup is done by
            #    _cleanup_pivot_old (rslave + umount via setns).
            pivot_script = (
                "mount --make-rslave / && "
                + hostname_cmd
                + f"cd {rootfs_q} && "
                "mkdir -p .pivot_old && "
                "pivot_root . .pivot_old && "
                "cd / && "
                f"exec setsid {seccomp_wrap}{shell_exec}"
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

        # Collect fds to pass to child
        _pass_fds = [signal_w]
        if self._userns and getattr(self, "_sync_fds", None):
            _pass_fds.append(self._sync_fds[0])  # sync_r

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
                pass_fds=tuple(_pass_fds),
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
                pass_fds=tuple(_pass_fds),
                start_new_session=True,
            )

        # Close write end in parent -- only the child should write to it.
        os.close(signal_w)
        self._signal_w = None

        # Full uid/gid mapping via newuidmap/newgidmap
        if self._userns and getattr(self, "_sync_fds", None):
            sync_r, sync_w = self._sync_fds
            os.close(sync_r)  # Close read end in parent

            pid = self._process.pid
            outer_uid, sub_start, sub_count = self._subuid_range

            # Wait for the child to enter the new user namespace
            my_userns = os.readlink("/proc/self/ns/user")
            for _ in range(1000):  # 1000 * 1ms = 1s max
                try:
                    child_userns = os.readlink(f"/proc/{pid}/ns/user")
                    if child_userns != my_userns:
                        break
                except (FileNotFoundError, PermissionError):
                    pass
                time.sleep(0.001)
            else:
                os.close(sync_w)
                raise RuntimeError(
                    f"Timed out waiting for user namespace creation (pid={pid})"
                )

            # Write full uid and gid mappings
            outer_gid = os.getgid()
            try:
                subprocess.run(
                    ["newuidmap", str(pid),
                     "0", str(outer_uid), "1",
                     "1", str(sub_start), str(sub_count)],
                    check=True, capture_output=True, text=True,
                )
                subprocess.run(
                    ["newgidmap", str(pid),
                     "0", str(outer_gid), "1",
                     "1", str(sub_start), str(sub_count)],
                    check=True, capture_output=True, text=True,
                )
            except subprocess.CalledProcessError as e:
                os.close(sync_w)
                raise RuntimeError(
                    f"Failed to set uid/gid mapping: {e.stderr.strip()}"
                ) from e

            logger.debug(
                "Full uid mapping set for pid %d: 0→%d, 1-%d→%d-%d",
                pid, outer_uid, sub_count, sub_start, sub_start + sub_count - 1,
            )

            # Signal child to proceed (close pipe → child's read returns EOF)
            os.close(sync_w)
            self._sync_fds = None

        # Security (mask/readonly/seccomp/cap-drop) is handled by adl-seccomp
        # which runs before the shell starts. Init script only does hostname + cd.
        _hostname_snippet = (
            f"echo {shlex.quote(self._hostname)} > /proc/sys/kernel/hostname 2>/dev/null || hostname {shlex.quote(self._hostname)} 2>/dev/null\n"
            if self._hostname else ""
        )

        if self._userns:
            # User namespace: adl-seccomp handles mask/readonly/seccomp/cap-drop.
            # Init script only does hostname + cd.
            init_script = (
                "PS1='' PS2=''\n"
                + _hostname_snippet
                + f"cd {shlex.quote(self._working_dir)} 2>/dev/null\n"
                f"echo 0 >&{self._signal_fd}\n"
            )
        else:
            # Rootful: adl-seccomp handles /proc, /dev, mask, readonly,
            # seccomp, cap-drop (all after pivot_root). Init = cd + signal.
            # When seccomp is off, adl-seccomp doesn't run so /proc isn't
            # mounted and read_only isn't applied. Handle both here.
            no_seccomp_init = ""
            if not self._seccomp:
                no_seccomp_init = "mount -t proc proc /proc 2>/dev/null\n"
            init_script = (
                "PS1='' PS2=''\n"
                + no_seccomp_init
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

        # Apply read-only rootfs after shell is ready. When seccomp is on,
        # adl-seccomp handles this; when off, we do it here (following
        # runc's ordering: mount /proc/dev → pivot_root → remount ro).
        if self._read_only and not self._seccomp:
            self.execute("mount -o remount,ro /", timeout=5)

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

    def _prepare_seccomp_helper(self) -> None:
        """Write seccomp BPF + static helper into rootfs /tmp.

        Called BEFORE pivot_root. The pivot_script then:
            exec setsid /tmp/.adl_seccomp /bin/sh
        The helper applies cap drop + mask + readonly + seccomp,
        then exec's the shell. No Python needed in rootfs.
        """
        from pathlib import Path
        from agentdocker_lite.security import build_seccomp_bpf

        bpf_bytes = build_seccomp_bpf()
        if bpf_bytes is None:
            return

        vendor_dir = Path(__file__).parent / "_vendor"
        helper_src = vendor_dir / "adl-seccomp"
        if not helper_src.exists():
            return

        tmp_dir = self._rootfs / "tmp"
        bpf_path = tmp_dir / ".adl_seccomp.bpf"
        # May already be written by _init_rootful (before read-only remount)
        if bpf_path.exists():
            return
        tmp_dir.mkdir(parents=True, exist_ok=True)

        import shutil
        bpf_path.write_bytes(bpf_bytes)
        shutil.copy2(str(helper_src), str(tmp_dir / ".adl_seccomp"))
        (tmp_dir / ".adl_seccomp").chmod(0o755)

    def _cleanup_pivot_old(self) -> None:
        """Unmount /.pivot_old inside the shell's mount namespace.

        After pivot_root, the old host root and all its submounts remain
        visible at /.pivot_old.  We clean them up from the host side by
        entering the mount namespace via setns.

        Critical safety steps (following runc pivotRoot pattern):
        1. setns into the container mount namespace
        2. Make /.pivot_old rslave (MS_SLAVE|MS_REC) so that the
           subsequent unmount does NOT propagate to the host
        3. umount2(/.pivot_old, MNT_DETACH)
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
        MS_SLAVE = 1 << 19        # 0x80000
        MS_REC = 1 << 14          # 0x4000
        CLONE_NEWNS = 0x00020000

        libc_name = ctypes.util.find_library("c")
        if not libc_name:
            return
        libc = ctypes.CDLL(libc_name, use_errno=True)
        # Set mount() arg/return types for safe ctypes calls.
        libc.mount.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_ulong, ctypes.c_char_p,
        ]
        libc.mount.restype = ctypes.c_int

        child_pid = os.fork()
        if child_pid == 0:
            # Child: enter mount namespace, chroot to target root,
            # then make old root rslave and unmount it.
            try:
                mnt_fd = os.open(mnt_ns, os.O_RDONLY)
                root_fd = os.open(root_path, os.O_RDONLY | os.O_DIRECTORY)
                rc = libc.setns(mnt_fd, CLONE_NEWNS)
                os.close(mnt_fd)
                if rc != 0:
                    # setns failed -- do NOT proceed in host namespace.
                    os.close(root_fd)
                    os._exit(1)
                # Align our root with the mount namespace root.
                os.fchdir(root_fd)
                os.chroot(".")
                os.close(root_fd)
                os.chdir("/")
                # Make old root rslave to prevent unmount propagation
                # to the host (runc approach: MS_SLAVE|MS_REC).
                libc.mount(b"", b"/.pivot_old", None, MS_SLAVE | MS_REC, None)
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
                if not events and self._process.poll() is not None:
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

        # Reached via break (e.g. PTY EIO) — return whatever we have.
        if buf:
            parts.append(buf.decode("utf-8", errors="backslashreplace"))
        return "".join(parts) if parts else None, exit_code if exit_code is not None else -1
