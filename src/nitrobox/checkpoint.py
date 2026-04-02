"""CRIU-based process checkpoint/restore for nitrobox sandboxes.

Provides full process-state snapshots (memory, registers, file descriptors)
on top of the existing overlayfs filesystem snapshots.  Zero runtime overhead —
CRIU only runs during save/restore operations.

Uses CRIU's ``swrk`` (service-worker) RPC protocol over Unix sockets for
reliable fd passing — the CLI mode does not support ``--inherit-fd``.

Requirements:
    - CRIU >= 4.0 (vendored static binary included)
    - Root or ``CAP_CHECKPOINT_RESTORE`` + ``CAP_SYS_PTRACE``
    - Kernel 5.9+ (for CAP_CHECKPOINT_RESTORE)
    - ``protobuf`` Python package

Usage:
    >>> from nitrobox import Sandbox, SandboxConfig
    >>> from nitrobox.checkpoint import CheckpointManager
    >>>
    >>> sb = Sandbox(SandboxConfig(image="ubuntu:22.04", working_dir="/workspace"))
    >>> mgr = CheckpointManager(sb)
    >>>
    >>> sb.run("export FOO=bar && cd /tmp")
    >>> mgr.save("/tmp/ckpt_v1")        # saves filesystem + process state
    >>> sb.run("rm -rf /workspace/*")   # destructive action
    >>> mgr.restore("/tmp/ckpt_v1")     # exact rollback: env vars, cwd, everything
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import shutil
import socket
import struct
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

# Lazy-import protobuf to avoid hard dependency at module level.
# The generated rpc_pb2 lives in _vendor/.
from typing import Any

# Protobuf-generated module with dynamic attributes — typed as Any to suppress
# attribute access errors from type checkers.
rpc: Any = __import__("nitrobox._vendor.criu_rpc_pb2", fromlist=["criu_rpc_pb2"])

if TYPE_CHECKING:
    from nitrobox.sandbox import Sandbox

logger = logging.getLogger(__name__)

_FS_DIR = "fs"
_CRIU_DIR = "criu"
_META_FILE = "meta.json"


# ------------------------------------------------------------------ #
#  CRIU binary discovery                                               #
# ------------------------------------------------------------------ #

def _find_criu() -> str:
    """Find the criu binary: vendored first, then system PATH."""
    vendored = Path(__file__).parent / "_vendor" / "criu"
    if vendored.is_file() and os.access(str(vendored), os.X_OK):
        return str(vendored)
    system = shutil.which("criu")
    if system:
        return system
    raise FileNotFoundError(
        "criu not found. Install it:\n"
        "  Arch:   pacman -S criu\n"
        "  Ubuntu: apt install criu\n"
        "  Fedora: dnf install criu"
    )


# ------------------------------------------------------------------ #
#  CRIU RPC client (minimal reimplementation of pycriu)                #
# ------------------------------------------------------------------ #

class _CriuRPC:
    """Minimal CRIU RPC client using ``criu swrk`` protocol.

    Communicates via a Unix SEQPACKET socketpair + protobuf,
    following the same protocol as pycriu / go-criu / libcriu.
    """

    def __init__(self, binary: str):
        self._binary = binary

    def _call(self, req: Any) -> Any:
        """Fork+exec ``criu swrk <fd>``, send request, receive response."""
        # Create socketpair: css[0] goes to child, css[1] stays in parent.
        css = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)

        # Child end: clear FD_CLOEXEC so it survives exec.
        flags = fcntl.fcntl(css[0], fcntl.F_GETFD)
        fcntl.fcntl(css[0], fcntl.F_SETFD, flags & ~fcntl.FD_CLOEXEC)
        # Parent end: set FD_CLOEXEC.
        flags = fcntl.fcntl(css[1], fcntl.F_GETFD)
        fcntl.fcntl(css[1], fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)

        pid = os.fork()
        if pid == 0:
            # Child: send our PID then exec criu swrk.
            try:
                css[0].send(struct.pack("i", os.getpid()))
                os.execv(
                    self._binary,
                    [self._binary, "swrk", str(css[0].fileno())],
                )
            except Exception:
                pass
            os._exit(1)

        # Parent: close child end, read child PID.
        css[0].close()
        sk = css[1]

        try:
            struct.unpack("i", sk.recv(4))  # read child PID (required by protocol)

            # Send protobuf request.
            sk.send(req.SerializeToString())

            # Receive response (peek for size first).
            peek = sk.recv(1, socket.MSG_TRUNC | socket.MSG_PEEK)
            buf = sk.recv(len(peek))

            resp = rpc.criu_resp()
            resp.ParseFromString(buf)
        finally:
            sk.close()
            os.waitpid(pid, 0)

        return resp

    def dump(self, opts: Any) -> Any:
        req = rpc.criu_req()
        req.type = rpc.DUMP
        req.opts.CopyFrom(opts)
        return self._call(req)

    def restore(self, opts: Any) -> Any:
        req = rpc.criu_req()
        req.type = rpc.RESTORE
        req.opts.CopyFrom(opts)
        return self._call(req)

    def check(self) -> bool:
        req = rpc.criu_req()
        req.type = rpc.CHECK
        req.opts.CopyFrom(rpc.criu_opts(images_dir_fd=-1))
        try:
            resp = self._call(req)
            return resp.success
        except Exception:
            return False


# ------------------------------------------------------------------ #
#  Helper functions                                                    #
# ------------------------------------------------------------------ #

def _get_pipe_fds(pid: int) -> list[str]:
    """Read stdin/stdout/stderr link targets from /proc/<pid>/fd.

    Returns a list of 3 strings like ``["pipe:[12345]", ...]``.
    Following runc's ``getPipeFds`` — only fds 0, 1, 2.
    """
    result: list[str] = ["", "", ""]
    for i in range(3):
        try:
            result[i] = os.readlink(f"/proc/{pid}/fd/{i}")
        except OSError:
            pass
    return result


def _get_all_pipe_inodes(pid: int) -> dict[int, int]:
    """Map fd numbers to pipe inodes for ALL fds of a process."""
    fd_dir = Path(f"/proc/{pid}/fd")
    result: dict[int, int] = {}
    try:
        for entry in fd_dir.iterdir():
            try:
                link = os.readlink(str(entry))
                if link.startswith("pipe:["):
                    result[int(entry.name)] = int(link[6:-1])
            except (OSError, ValueError):
                continue
    except OSError:
        pass
    return result


def _find_init_pid(shell_pid: int) -> int:
    """Find PID 1 inside the namespace (the bash process)."""
    try:
        children = Path(
            f"/proc/{shell_pid}/task/{shell_pid}/children"
        ).read_text().strip().split()
        if children:
            return int(children[0])
    except (OSError, ValueError):
        pass
    return shell_pid


# ------------------------------------------------------------------ #
#  CheckpointManager                                                   #
# ------------------------------------------------------------------ #

class CheckpointManager:
    """Manages CRIU checkpoint/restore for a sandbox instance.

    Args:
        sandbox: A running Sandbox instance (must be rootful mode).
        criu_binary: Path to criu binary. Auto-detected if None.
    """

    def __init__(
        self,
        sandbox: Sandbox,
        criu_binary: str | None = None,
    ):
        self._sandbox = sandbox
        self._criu_path = criu_binary or _find_criu()
        self._rpc = _CriuRPC(self._criu_path)

        if os.geteuid() != 0:
            raise PermissionError(
                "CheckpointManager requires root "
                "(CRIU needs CAP_CHECKPOINT_RESTORE + CAP_SYS_PTRACE)"
            )

        # Become a subreaper so CRIU-restored processes (whose parent
        # is the exited criu swrk) get reparented to us instead of
        # init.  This lets waitpid work and avoids zombies.
        import ctypes
        import ctypes.util
        PR_SET_CHILD_SUBREAPER = 36
        _libc_name = ctypes.util.find_library("c")
        if _libc_name:
            _libc = ctypes.CDLL(_libc_name, use_errno=True)
            _libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)

    def save(
        self,
        path: str,
        *,
        leave_running: bool = True,
        track_mem: bool = True,
    ) -> None:
        """Checkpoint the sandbox: filesystem + full process state.

        Args:
            path: Directory to save checkpoint to (must not exist).
            leave_running: Keep sandbox alive after checkpoint.
            track_mem: Enable memory change tracking (PAGEMAP_SCAN).
        """
        ckpt_dir = Path(path)
        if ckpt_dir.exists():
            raise FileExistsError(f"Checkpoint directory already exists: {path}")
        ckpt_dir.mkdir(parents=True)

        fs_dir = ckpt_dir / _FS_DIR
        criu_dir = ckpt_dir / _CRIU_DIR
        criu_dir.mkdir()

        # 1. Save filesystem state.
        self._sandbox.fs_snapshot(str(fs_dir))

        # 2. Identify target process.
        shell = self._sandbox._persistent_shell
        if not shell.alive:
            raise RuntimeError("Sandbox shell is not running")
        shell_pid = shell.pid
        assert shell_pid is not None, "shell has no pid"
        init_pid = _find_init_pid(shell_pid)

        # 3. Save pipe descriptors (runc approach: readlink fd 0/1/2).
        pipe_fds = _get_pipe_fds(init_pid)
        all_pipe_inodes = _get_all_pipe_inodes(init_pid)
        signal_fd = shell._signal_fd

        meta = {
            "shell_pid": shell_pid,
            "init_pid": init_pid,
            "signal_fd": signal_fd,
            "pipe_fds": pipe_fds,  # ["pipe:[X]", "pipe:[Y]", "pipe:[Y]"]
            "all_pipe_inodes": {str(k): v for k, v in all_pipe_inodes.items()},
            "tty": self._sandbox._config.tty,
            "working_dir": self._sandbox._config.working_dir,
        }
        # Save pipe_fds as descriptors.json (runc convention).
        (criu_dir / "descriptors.json").write_text(json.dumps(pipe_fds))
        (ckpt_dir / _META_FILE).write_text(json.dumps(meta, indent=2))

        # 4. Build CRIU dump options.
        rootfs = self._sandbox._rootfs
        opts = rpc.criu_opts()
        opts.images_dir_fd = os.open(str(criu_dir), os.O_DIRECTORY)
        opts.pid = init_pid
        opts.root = str(rootfs)
        opts.log_file = "dump.log"
        opts.log_level = 4
        opts.shell_job = True
        opts.tcp_established = True
        opts.evasive_devices = True
        opts.ghost_limit = 10 * 1024 * 1024
        opts.orphan_pts_master = True

        if leave_running:
            opts.leave_running = True
        if track_mem:
            opts.track_mem = True

        # External mounts: /proc, /dev, and all user-configured volumes.
        # Following runc: register every non-rootfs mount as external so
        # CRIU doesn't try to dump/restore them (they're managed by us).
        ext_mounts = ["/proc", "/dev"]
        for bind_path in getattr(self._sandbox, "_bind_mounts", []):
            # Convert host path to container-relative path.
            try:
                rel = "/" + str(bind_path.relative_to(rootfs))
            except ValueError:
                rel = str(bind_path)
            ext_mounts.append(rel)

        for mnt in ext_mounts:
            ext = opts.ext_mnt.add()
            ext.key = mnt
            ext.val = mnt

        # External pipes (all pipe fds).
        for _, inode in all_pipe_inodes.items():
            opts.external.append(f"pipe:[{inode}]")

        # 5. Run CRIU dump.
        logger.info("CRIU dump: pid=%d dir=%s", init_pid, criu_dir)
        try:
            resp = self._rpc.dump(opts)
        finally:
            os.close(opts.images_dir_fd)

        if not resp.success:
            log_file = criu_dir / "dump.log"
            criu_log = log_file.read_text()[-2000:] if log_file.exists() else ""
            raise RuntimeError(
                f"CRIU dump failed (errno={resp.cr_errno}):\n"
                f"log (tail): {criu_log}"
            )

        logger.info("Checkpoint saved: %s", path)

    def restore(self, path: str) -> None:
        """Restore sandbox to a previously saved checkpoint.

        Args:
            path: Directory containing a previous save().
        """
        ckpt_dir = Path(path)
        if not ckpt_dir.exists():
            raise FileNotFoundError(f"Checkpoint not found: {path}")

        fs_dir = ckpt_dir / _FS_DIR
        criu_dir = ckpt_dir / _CRIU_DIR
        meta_file = ckpt_dir / _META_FILE

        if not criu_dir.exists() or not meta_file.exists():
            raise FileNotFoundError(f"Invalid checkpoint: {path}")

        meta = json.loads(meta_file.read_text())
        pipe_fds: list[str] = meta["pipe_fds"]
        all_pipe_inodes: dict[str, int] = meta.get("all_pipe_inodes", {})
        signal_fd_num = meta["signal_fd"]
        use_tty = bool(meta.get("tty"))

        shell = self._sandbox._persistent_shell

        # 1. Kill current shell.
        shell.kill()

        # 2. Restore filesystem.
        #    Replace upper layer, then remount overlayfs to flush kernel
        #    inode cache (overlayfs doesn't auto-reflect upper dir changes).
        upper = getattr(self._sandbox, "_upper_dir", None)
        if upper:
            rootfs = self._sandbox._rootfs
            # Unmount overlayfs.
            from nitrobox._core import py_umount
            try:
                py_umount(str(rootfs))
            except OSError:
                pass
            # Replace upper layer.
            if upper.exists():
                shutil.rmtree(upper)
            shutil.copytree(str(fs_dir), str(upper))
            # Clear work dir.
            work = getattr(self._sandbox, "_work_dir", None)
            if work and work.exists():
                shutil.rmtree(work)
                work.mkdir(parents=True)
            # Remount overlayfs.
            lowerdir_spec = getattr(self._sandbox, "_lowerdir_spec", None)
            if not lowerdir_spec:
                base_rootfs = getattr(self._sandbox, "_base_rootfs", None)
                lowerdir_spec = str(base_rootfs) if base_rootfs else None
            if lowerdir_spec:
                from nitrobox._core import py_mount_overlay

                py_mount_overlay(
                    lowerdir_spec=str(lowerdir_spec),
                    upper_dir=str(upper),
                    work_dir=str(work),
                    target=str(rootfs),
                )

        # 3. Create new pipes for the restored process.
        signal_r, signal_w = os.pipe()

        if use_tty:
            import pty as pty_mod
            import termios
            master_fd, slave_fd = pty_mod.openpty()
            attrs = termios.tcgetattr(master_fd)
            attrs[3] &= ~termios.ECHO
            termios.tcsetattr(master_fd, termios.TCSANOW, attrs)
            stdin_r = stdin_w = stdout_r = stdout_w = stderr_w = -1
        else:
            master_fd = slave_fd = -1
            stdin_r, stdin_w = os.pipe()
            stdout_r, stdout_w = os.pipe()
            stderr_w = os.dup(stdout_w)

        # Make all fds inheritable so criu swrk's fork can see them.
        new_fds = [signal_w]
        if use_tty:
            new_fds.append(slave_fd)
        else:
            new_fds.extend([stdin_r, stdout_w, stderr_w])
        for fd in new_fds:
            os.set_inheritable(fd, True)

        # 4. Build CRIU restore options.
        #    The "criu-root" bind mount trick from runc: CRIU requires
        #    --root to be a mount point whose parent is NOT overmounted.
        #    We bind-mount the rootfs to a temporary directory to
        #    guarantee this invariant regardless of the host layout.
        rootfs = self._sandbox._rootfs
        env_dir = getattr(self._sandbox, "_env_dir", None)
        criu_root = Path(str(env_dir or rootfs.parent)) / "criu-root"
        criu_root.mkdir(exist_ok=True)
        from nitrobox._core import py_rbind_mount
        py_rbind_mount(str(rootfs), str(criu_root))
        opts = rpc.criu_opts()
        opts.images_dir_fd = os.open(str(criu_dir), os.O_DIRECTORY)
        opts.root = str(criu_root)
        opts.log_file = "restore.log"
        opts.log_level = 4
        opts.shell_job = True
        opts.tcp_established = True
        opts.evasive_devices = True
        opts.rst_sibling = True
        opts.orphan_pts_master = True

        # External mounts (must match dump registration).
        ext_mounts = ["/proc", "/dev"]
        for bind_path in getattr(self._sandbox, "_bind_mounts", []):
            try:
                rel = "/" + str(bind_path.relative_to(rootfs))
            except ValueError:
                rel = str(bind_path)
            ext_mounts.append(rel)

        for mnt in ext_mounts:
            ext = opts.ext_mnt.add()
            ext.key = mnt
            ext.val = mnt

        # Inherit fds: reconnect pipes.
        # Signal pipe (find its inode from all_pipe_inodes).
        signal_inode_key = None
        for fd_str, inode in all_pipe_inodes.items():
            if int(fd_str) == signal_fd_num:
                signal_inode_key = f"pipe:[{inode}]"
                break
        if signal_inode_key:
            inhfd = opts.inherit_fd.add()
            inhfd.key = signal_inode_key
            inhfd.fd = signal_w

        # stdin/stdout/stderr pipes (runc approach: use pipe_fds list).
        if use_tty:
            for i, desc in enumerate(pipe_fds):
                if desc and "pipe:" in desc:
                    inhfd = opts.inherit_fd.add()
                    inhfd.key = desc
                    inhfd.fd = slave_fd
        else:
            # Each inherit_fd entry must use a UNIQUE fd because
            # CRIU closes the fd after consuming it.
            fd_map = {0: stdin_r, 1: stdout_w, 2: stderr_w}
            for i, desc in enumerate(pipe_fds):
                if desc and "pipe:" in desc and i in fd_map:
                    inhfd = opts.inherit_fd.add()
                    inhfd.key = desc
                    inhfd.fd = fd_map[i]

        # 5. Run CRIU restore.
        logger.info("CRIU restore: dir=%s", criu_dir)
        all_cleanup_fds = [
            signal_r, signal_w,
            *(([master_fd, slave_fd] if use_tty else
               [stdin_r, stdin_w, stdout_r, stdout_w, stderr_w])),
        ]

        def _cleanup_criu_root():
            subprocess.run(
                ["umount", "-l", str(criu_root)],
                capture_output=True,
            )
            try:
                criu_root.rmdir()
            except OSError:
                pass

        try:
            resp = self._rpc.restore(opts)
        except Exception:
            for fd in all_cleanup_fds:
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            os.close(opts.images_dir_fd)
            _cleanup_criu_root()
            raise
        finally:
            os.close(opts.images_dir_fd)

        _cleanup_criu_root()

        if not resp.success:
            for fd in all_cleanup_fds:
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            log_file = criu_dir / "restore.log"
            criu_log = log_file.read_text()[-2000:] if log_file.exists() else ""
            raise RuntimeError(
                f"CRIU restore failed (errno={resp.cr_errno}):\n"
                f"log (tail): {criu_log}"
            )

        restored_pid = resp.restore.pid

        # 6. Close fds passed to the restored process.
        os.close(signal_w)
        if use_tty:
            os.close(slave_fd)
        else:
            os.close(stdin_r)
            os.close(stdout_w)
            os.close(stderr_w)

        # 7. Reconnect shell object.
        shell._signal_r = signal_r
        shell._signal_fd = signal_fd_num

        shell.pid = restored_pid
        if use_tty:
            shell._master_fd = master_fd
            shell._stdin_fd = master_fd
            shell._stdout_fd = master_fd
        else:
            shell._master_fd = None
            shell._stdin_fd = stdin_w
            shell._stdout_fd = stdout_r

        if hasattr(self._sandbox, "_bg_handles"):
            self._sandbox._bg_handles.clear()

        logger.info("Checkpoint restored: %s (pid=%d)", path, restored_pid)

    @staticmethod
    def check_available() -> bool:
        """Check if CRIU is installed and the kernel supports it."""
        try:
            criu = _find_criu()
            rpc_client = _CriuRPC(criu)
            return rpc_client.check()
        except (FileNotFoundError, Exception):
            return False


# ------------------------------------------------------------------ #
#  Popen-like wrapper for CRIU-restored processes                      #
# ------------------------------------------------------------------ #

class _RestoredProcess:
    """Minimal Popen-like wrapper for a CRIU-restored process.

    Provides the interface that _PersistentShell needs:
    .pid, .poll(), .stdin, .stdout, .kill(), .wait().
    """

    def __init__(self, pid: int, stdin_fd: int, stdout_fd: int):
        self.pid = pid
        self._dead = False
        from nitrobox._core import py_pidfd_open
        self._pidfd: int | None = py_pidfd_open(pid)
        self.stdin = os.fdopen(stdin_fd, "wb", buffering=0) if stdin_fd >= 0 else None
        self.stdout = os.fdopen(stdout_fd, "rb", buffering=0) if stdout_fd >= 0 else None

    def poll(self) -> int | None:
        if self._dead:
            return -1
        # With subreaper, the restored process is our adopted child,
        # so waitpid works normally.
        try:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid == 0:
                return None
            self._dead = True
            return os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1
        except ChildProcessError:
            # Not our child (subreaper not set or race) — fallback to pidfd.
            if self._pidfd is not None:
                from nitrobox._core import py_pidfd_is_alive
                if not py_pidfd_is_alive(self._pidfd):
                    self._dead = True
                    return -1
                return None
            if not Path(f"/proc/{self.pid}").exists():
                self._dead = True
                return -1
            return None
        # Fallback to waitpid / /proc check.
        try:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid == 0:
                return None
            return os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1
        except ChildProcessError:
            if Path(f"/proc/{self.pid}").exists():
                return None
            return -1

    def kill(self) -> None:
        import signal
        # Try kill single process first (restored process may not be
        # a process group leader, so killpg can fail).
        try:
            os.kill(self.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.killpg(self.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        self._dead = True
        if self._pidfd is not None:
            try:
                os.close(self._pidfd)
            except OSError:
                pass
            self._pidfd = None

    def wait(self, timeout: float | None = None) -> int:
        import time
        deadline = time.monotonic() + timeout if timeout is not None else None
        while True:
            ret = self.poll()
            if ret is not None:
                return ret
            if deadline is not None and time.monotonic() > deadline:
                raise subprocess.TimeoutExpired(
                    cmd="criu-restored", timeout=timeout or 0,
                )
            time.sleep(0.01)
