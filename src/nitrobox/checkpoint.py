"""CRIU-based process checkpoint/restore for nitrobox sandboxes.

Uses ``nitrobox-core checkpoint-dump/restore`` which internally uses the
go-criu library to communicate with CRIU. The custom CRIU binary (with
rootless patches) is found automatically.

Requirements:
    - ``nitrobox setup`` must have been run (installs CRIU + helper)
    - Kernel 5.9+ (for CAP_CHECKPOINT_RESTORE)
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


def _find_helper() -> str:
    """Find the setuid checkpoint helper binary."""
    for p in ["/usr/local/bin/nitrobox-checkpoint-helper",
              "/usr/bin/nitrobox-checkpoint-helper"]:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    vendored = Path(__file__).parent / "_vendor" / "nitrobox-checkpoint-helper"
    if vendored.is_file():
        return str(vendored)
    system = shutil.which("nitrobox-checkpoint-helper")
    if system:
        return system
    raise FileNotFoundError(
        "nitrobox-checkpoint-helper not found. Run 'nitrobox setup'."
    )


def _find_criu() -> str:
    """Find the CRIU binary (prefer system-installed with file capabilities)."""
    p = os.environ.get("NITROBOX_CRIU_PATH")
    if p:
        return p
    # System-installed CRIU has file capabilities from 'nitrobox setup'
    for candidate in ["/usr/local/bin/criu", "/usr/bin/criu"]:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    # Vendored fallback (may lack capabilities)
    vendored = Path(__file__).parent / "_vendor" / "criu"
    if vendored.is_file():
        return str(vendored)
    raise FileNotFoundError("criu not found")


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
    """Find the shell process inside the namespace."""
    try:
        children = Path(
            f"/proc/{shell_pid}/task/{shell_pid}/children"
        ).read_text().strip().split()
        if children:
            return int(children[0])
    except (OSError, ValueError):
        pass
    return shell_pid


class CheckpointManager:
    """Manages CRIU checkpoint/restore for a sandbox instance.

    Uses ``nitrobox-core`` with go-criu for checkpoint operations.
    """

    def __init__(self, sandbox: Sandbox, helper_binary: str | None = None):
        self._sandbox = sandbox
        self._helper = helper_binary or _find_helper()
        # Become a subreaper so CRIU-restored processes get reparented to us
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        libc.prctl(36, 1, 0, 0, 0)  # PR_SET_CHILD_SUBREAPER

    def save(self, path: str, *, leave_running: bool = True, track_mem: bool = True) -> None:
        """Checkpoint the sandbox: filesystem + full process state."""
        ckpt_dir = Path(path)
        if ckpt_dir.exists():
            raise FileExistsError(f"Checkpoint directory already exists: {path}")
        ckpt_dir.mkdir(parents=True)

        fs_dir = ckpt_dir / _FS_DIR
        criu_dir = ckpt_dir / _CRIU_DIR
        criu_dir.mkdir()

        # 1. Save filesystem state (overlay upper dir).
        self._sandbox.fs_snapshot(str(fs_dir))

        # 2. Identify target process.
        shell = self._sandbox._persistent_shell
        if not shell.alive:
            raise RuntimeError("Sandbox shell is not running")
        shell_pid = shell.pid
        init_pid = _find_init_pid(shell_pid)

        # 3. Save metadata.
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
        }
        (ckpt_dir / _META_FILE).write_text(json.dumps(meta, indent=2))

        # 4. Build dump command.
        ext_mounts = ["/proc", "/dev"]
        external_pipes = [f"pipe:[{inode}]" for _, inode in all_pipe_inodes.items()]

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

        # 5. Run helper dump.
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
        """Restore sandbox to a previously saved checkpoint."""
        ckpt_dir = Path(path)
        if not ckpt_dir.exists():
            raise FileNotFoundError(f"Checkpoint not found: {path}")

        criu_dir = ckpt_dir / _CRIU_DIR
        meta_file = ckpt_dir / _META_FILE
        fs_dir = ckpt_dir / _FS_DIR

        meta = json.loads(meta_file.read_text())
        pipe_fds: list[str] = meta["pipe_fds"]
        all_pipe_inodes: dict[str, int] = meta.get("all_pipe_inodes", {})
        signal_fd_num = meta["signal_fd"]
        use_tty = bool(meta.get("tty"))

        shell = self._sandbox._persistent_shell

        # 1. Kill current shell.
        shell.kill()

        # 2. Restore filesystem.
        upper = getattr(self._sandbox, "_upper_dir", None)
        if upper:
            rootfs = self._sandbox._rootfs
            from nitrobox._backend import py_umount
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

        # 3. Remount overlay.
        lowerdir_spec = getattr(self._sandbox, "_lowerdir_spec", None)
        if not lowerdir_spec:
            base_rootfs = getattr(self._sandbox, "_base_rootfs", None)
            lowerdir_spec = str(base_rootfs) if base_rootfs else None
        if lowerdir_spec and upper:
            rootfs = self._sandbox._rootfs
            work = getattr(self._sandbox, "_work_dir", None)
            from nitrobox._backend import py_mount_overlay
            try:
                py_mount_overlay(str(lowerdir_spec), str(upper), str(work), str(rootfs))
            except OSError:
                pass
            self._sandbox._overlay_mounted = True

        # 4. Create new pipes for the restored process.
        signal_r, signal_w = os.pipe()
        if use_tty:
            import pty as pty_mod, termios
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

        # 5. Build inherit-fd mappings.
        inherit_fds = []
        for fd_str, inode in all_pipe_inodes.items():
            if int(fd_str) == signal_fd_num:
                inherit_fds.append({"key": f"pipe:[{inode}]", "fd": signal_w})
                break
        if use_tty:
            for desc in pipe_fds:
                if desc and "pipe:" in desc:
                    inherit_fds.append({"key": desc, "fd": slave_fd})
        else:
            fd_map = {0: stdin_r, 1: stdout_w, 2: stderr_w}
            for i, desc in enumerate(pipe_fds):
                if desc and "pipe:" in desc and i in fd_map:
                    inherit_fds.append({"key": desc, "fd": fd_map[i]})

        rootfs = str(self._sandbox._rootfs)
        pidfile = criu_dir / "restore.pid"
        all_pass_fds = tuple(fd for fd in new_fds if fd >= 0)

        # 6. Run helper restore.
        cmd = [
            self._helper, "restore",
            "--ns-pid", str(os.getpid()),
            "--images-dir", str(criu_dir),
            "--root", rootfs,
            "--shell-job",
            "--restore-sibling",
            "--restore-detached",
            "--mntns-compat-mode",
            "--pidfile", str(pidfile),
        ]
        for ifd in inherit_fds:
            cmd.extend(["--inherit-fd", f"fd[{ifd['fd']}]:{ifd['key']}"])

        result = subprocess.run(
            cmd, capture_output=True, text=True,
            close_fds=False, pass_fds=all_pass_fds,
        )

        # Close child-side fds.
        os.close(signal_w)
        if use_tty:
            os.close(slave_fd)
        else:
            os.close(stdin_r)
            os.close(stdout_w)
            os.close(stderr_w)

        if result.returncode != 0:
            for fd in [signal_r] + ([master_fd] if use_tty else [stdin_w, stdout_r]):
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

        # 7. Reconnect shell.
        shell.pid = restored_pid
        shell._signal_r = signal_r
        shell._signal_fd = signal_fd_num
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
        """Check if CRIU is available."""
        try:
            _find_criu()
            return True
        except FileNotFoundError:
            return False
