"""CRIU-based process checkpoint/restore for nitrobox sandboxes.

Provides full process-state snapshots (memory, registers, file descriptors)
on top of the existing overlayfs filesystem snapshots.  Zero runtime overhead —
CRIU only runs during save/restore operations.

Uses ``nitrobox-checkpoint-helper`` — a setuid binary installed by
``nitrobox setup`` that runs CRIU with full root privileges.  The
training script itself runs as a normal user.

Requirements:
    - ``nitrobox setup`` must have been run (installs helper + CRIU)
    - Kernel 5.9+ (for CAP_CHECKPOINT_RESTORE)

Usage:
    >>> from nitrobox import Sandbox, SandboxConfig
    >>> from nitrobox.checkpoint import CheckpointManager
    >>>
    >>> box = Sandbox(SandboxConfig(image="ubuntu:22.04", working_dir="/workspace"))
    >>> mgr = CheckpointManager(box)
    >>>
    >>> box.run("export FOO=bar && cd /tmp")
    >>> mgr.save("/tmp/ckpt_v1")        # saves filesystem + process state
    >>> box.run("rm -rf /workspace/*")   # destructive action
    >>> mgr.restore("/tmp/ckpt_v1")     # exact rollback: env vars, cwd, everything
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nitrobox.sandbox import Sandbox

logger = logging.getLogger(__name__)

_FS_DIR = "fs"
_CRIU_DIR = "criu"
_META_FILE = "meta.json"


# ------------------------------------------------------------------ #
#  Binary discovery                                                    #
# ------------------------------------------------------------------ #

def _find_helper() -> str:
    """Find the nitrobox-checkpoint-helper binary."""
    # 1. System path
    system = shutil.which("nitrobox-checkpoint-helper")
    if system:
        return system
    # 2. Next to vendored CRIU
    vendored = Path(__file__).parent / "_vendor" / "nitrobox-checkpoint-helper"
    if vendored.is_file() and os.access(str(vendored), os.X_OK):
        return str(vendored)
    raise FileNotFoundError(
        "nitrobox-checkpoint-helper not found.\n"
        "Run 'nitrobox setup' to install it."
    )


def _find_criu() -> str:
    """Find the criu binary (for check_available only)."""
    vendored = Path(__file__).parent / "_vendor" / "criu"
    if vendored.is_file() and os.access(str(vendored), os.X_OK):
        return str(vendored)
    system = shutil.which("criu")
    if system:
        return system
    raise FileNotFoundError("criu not found")


# ------------------------------------------------------------------ #
#  Helper functions                                                    #
# ------------------------------------------------------------------ #

def _get_pipe_fds(pid: int) -> list[str]:
    """Read stdin/stdout/stderr link targets from /proc/<pid>/fd."""
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
    """Find the bash process inside the namespace."""
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

    Uses the setuid ``nitrobox-checkpoint-helper`` binary for full
    rootful CRIU capability without requiring sudo in the calling process.

    Run ``nitrobox setup`` to install the helper.
    """

    def __init__(
        self,
        sandbox: Sandbox,
        helper_binary: str | None = None,
    ):
        self._sandbox = sandbox
        self._helper = helper_binary or _find_helper()

        # Become a subreaper so CRIU-restored processes get reparented
        # to us instead of init.
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

        # 3. Save pipe descriptors.
        pipe_fds = _get_pipe_fds(init_pid)
        all_pipe_inodes = _get_all_pipe_inodes(init_pid)
        signal_fd = shell._signal_fd

        meta = {
            "shell_pid": shell_pid,
            "init_pid": init_pid,
            "signal_fd": signal_fd,
            "pipe_fds": pipe_fds,
            "all_pipe_inodes": {str(k): v for k, v in all_pipe_inodes.items()},
            "tty": self._sandbox._config.tty,
            "working_dir": self._sandbox._config.working_dir,
        }
        (criu_dir / "descriptors.json").write_text(json.dumps(pipe_fds))
        (ckpt_dir / _META_FILE).write_text(json.dumps(meta, indent=2))

        # 4. Build external mounts and pipes.
        rootfs = self._sandbox._rootfs
        ext_mounts = ["/proc", "/dev"]
        for bind_path in getattr(self._sandbox, "_bind_mounts", []):
            try:
                rel = "/" + str(bind_path.relative_to(rootfs))
            except ValueError:
                rel = str(bind_path)
            ext_mounts.append(rel)

        external_pipes = [f"pipe:[{inode}]" for _, inode in all_pipe_inodes.items()]

        # 5. Run helper dump.
        #    Helper enters sandbox's namespaces (as root via setuid),
        #    Helper enters sandbox's mount namespace (as root via setuid),
        #    runs CRIU from inside — same view as runc/Docker.
        cmd = [
            self._helper, "dump",
            "--ns-pid", str(init_pid),
            "--tree", str(init_pid),
            "--images-dir", str(criu_dir),
            "--shell-job",
        ]
        if leave_running:
            cmd.append("--leave-running")
        if track_mem:
            cmd.append("--track-mem")
        for mnt in ext_mounts:
            cmd.extend(["--ext-mount-map", f"{mnt}:{mnt}"])
        for pipe in external_pipes:
            cmd.extend(["--external", pipe])

        logger.info("CRIU dump: pid=%d dir=%s", init_pid, criu_dir)
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            log_file = criu_dir / "dump.log"
            criu_log = log_file.read_text()[-2000:] if log_file.exists() else ""
            raise RuntimeError(
                f"CRIU dump failed (exit={result.returncode}):\n"
                f"stderr: {result.stderr.strip()}\n"
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

        # 2. Restore filesystem (replace overlay upper dir).
        upper = getattr(self._sandbox, "_upper_dir", None)
        if upper:
            rootfs = self._sandbox._rootfs
            from nitrobox._core import py_umount
            try:
                py_umount(str(rootfs))
            except OSError:
                pass
            if upper.exists():
                if getattr(self._sandbox, "_userns", False):
                    from nitrobox.image.layers import rmtree_mapped
                    rmtree_mapped(upper)
                else:
                    shutil.rmtree(upper)
            shutil.copytree(str(fs_dir), str(upper))
            work = getattr(self._sandbox, "_work_dir", None)
            if work and work.exists():
                if getattr(self._sandbox, "_userns", False):
                    from nitrobox.image.layers import rmtree_mapped
                    rmtree_mapped(work)
                else:
                    shutil.rmtree(work)
                work.mkdir(parents=True, exist_ok=True)

        # 3. Mount overlay (helper does it as root).
        lowerdir_spec = getattr(self._sandbox, "_lowerdir_spec", None)
        if not lowerdir_spec:
            base_rootfs = getattr(self._sandbox, "_base_rootfs", None)
            lowerdir_spec = str(base_rootfs) if base_rootfs else None
        if lowerdir_spec and upper:
            rootfs = self._sandbox._rootfs
            work = getattr(self._sandbox, "_work_dir", None)
            from nitrobox._core import py_mount_overlay
            try:
                py_mount_overlay(
                    lowerdir_spec=str(lowerdir_spec),
                    upper_dir=str(upper),
                    work_dir=str(work),
                    target=str(rootfs),
                )
            except OSError:
                subprocess.run(
                    [self._helper, "mount-overlay",
                     "--lowerdir", str(lowerdir_spec),
                     "--upper", str(upper),
                     "--work", str(work),
                     "--target", str(rootfs)],
                    check=True, capture_output=True,
                )
            self._sandbox._overlay_mounted = True

        # 4. Create new pipes for the restored process.
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

        new_fds = [signal_w]
        if use_tty:
            new_fds.append(slave_fd)
        else:
            new_fds.extend([stdin_r, stdout_w, stderr_w])
        for fd in new_fds:
            os.set_inheritable(fd, True)

        # 5. Build inherit-fd args.
        inherit_fds: list[tuple[str, int]] = []
        for fd_str, inode in all_pipe_inodes.items():
            if int(fd_str) == signal_fd_num:
                inherit_fds.append((f"pipe:[{inode}]", signal_w))
                break
        if use_tty:
            for desc in pipe_fds:
                if desc and "pipe:" in desc:
                    inherit_fds.append((desc, slave_fd))
        else:
            fd_map = {0: stdin_r, 1: stdout_w, 2: stderr_w}
            for i, desc in enumerate(pipe_fds):
                if desc and "pipe:" in desc and i in fd_map:
                    inherit_fds.append((desc, fd_map[i]))

        all_cleanup_fds = [
            signal_r, signal_w,
            *(([master_fd, slave_fd] if use_tty else
               [stdin_r, stdin_w, stdout_r, stdout_w, stderr_w])),
        ]
        all_pass_fds = tuple(fd for fd in new_fds if fd >= 0)

        # 6. Run helper restore.
        #    Helper runs CRIU from init namespace with full root.
        #    CRIU recreates all namespaces from checkpoint images.
        #    --root points to the overlay-mounted rootfs.
        rootfs = self._sandbox._rootfs
        pidfile = criu_dir / "restore.pid"
        cmd = [
            self._helper, "restore",
            "--ns-pid", str(os.getpid()),  # for ownership check only
            "--images-dir", str(criu_dir),
            "--root", str(rootfs),
            "--shell-job",
            "--restore-sibling",
            "--restore-detached",
            "--mntns-compat-mode",
            "--pidfile", str(pidfile),
        ]
        for key, fd in inherit_fds:
            cmd.extend(["--inherit-fd", f"fd[{fd}]:{key}"])

        logger.info("CRIU restore: dir=%s", criu_dir)
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                close_fds=False, pass_fds=all_pass_fds,
            )
        except Exception:
            for fd in all_cleanup_fds:
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            raise

        if result.returncode != 0:
            for fd in all_cleanup_fds:
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            log_file = criu_dir / "restore.log"
            criu_log = log_file.read_text()[-2000:] if log_file.exists() else ""
            raise RuntimeError(
                f"CRIU restore failed (exit={result.returncode}):\n"
                f"stderr: {result.stderr.strip()}\n"
                f"log (tail): {criu_log}"
            )

        restored_pid = int(pidfile.read_text().strip())
        shell.kill()

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
        """Check if checkpoint helper and CRIU are available."""
        try:
            _find_helper()
            _find_criu()
            return True
        except FileNotFoundError:
            return False
