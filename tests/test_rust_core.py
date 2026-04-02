"""Tests for Rust core bindings: mount, nsenter, fuser."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path

import pytest

from nitrobox._core import (
    py_bind_mount,
    py_fuser_kill,
    py_make_private,
    py_nsenter_preexec,
    py_rbind_mount,
    py_remount_ro_bind,
    py_umount,
    py_umount_lazy,
    py_umount_recursive_lazy,
    py_userns_preexec,
)


def _requires_root():
    if os.geteuid() != 0:
        pytest.skip("requires root")


# ================================================================== #
#  Mount operations (require root)                                     #
# ================================================================== #


class TestBindMount:
    """Bind mount and unmount via Rust syscalls."""

    def test_bind_mount_and_umount(self, tmp_path):
        """Bind mount a directory, verify content visible, then unmount."""
        _requires_root()

        src = tmp_path / "src"
        src.mkdir()
        (src / "hello.txt").write_text("world")

        target = tmp_path / "target"
        target.mkdir()

        py_bind_mount(str(src), str(target))
        try:
            assert (target / "hello.txt").read_text() == "world"
        finally:
            py_umount(str(target))

        # After unmount, target is empty again.
        assert not (target / "hello.txt").exists()

    def test_bind_mount_read_only(self, tmp_path):
        """Bind mount + remount ro prevents writes."""
        _requires_root()

        src = tmp_path / "src"
        src.mkdir()
        (src / "data.txt").write_text("original")

        target = tmp_path / "target"
        target.mkdir()

        py_bind_mount(str(src), str(target))
        py_remount_ro_bind(str(target))
        try:
            assert (target / "data.txt").read_text() == "original"
            with pytest.raises(OSError):
                (target / "new.txt").write_text("fail")
        finally:
            py_umount(str(target))

    def test_umount_lazy(self, tmp_path):
        """Lazy unmount succeeds even if mount is busy."""
        _requires_root()

        src = tmp_path / "src"
        src.mkdir()
        target = tmp_path / "target"
        target.mkdir()

        py_bind_mount(str(src), str(target))
        py_umount_lazy(str(target))

    def test_umount_nonexistent_raises(self):
        """Unmounting a non-mount-point raises OSError."""
        _requires_root()
        with pytest.raises(OSError):
            py_umount("/tmp/.nitrobox_nonexistent_test_mount")

    def test_rbind_mount(self, tmp_path):
        """Recursive bind mount includes sub-mounts."""
        _requires_root()

        src = tmp_path / "src"
        src.mkdir()
        (src / "file.txt").write_text("content")

        target = tmp_path / "target"
        target.mkdir()

        py_rbind_mount(str(src), str(target))
        try:
            assert (target / "file.txt").read_text() == "content"
        finally:
            py_umount_lazy(str(target))

    def test_make_private(self, tmp_path):
        """Make a mount point private (no propagation)."""
        _requires_root()

        src = tmp_path / "src"
        src.mkdir()
        target = tmp_path / "target"
        target.mkdir()

        py_bind_mount(str(src), str(target))
        try:
            py_make_private(str(target))
        finally:
            py_umount(str(target))


class TestRecursiveUmount:
    """Recursive lazy unmount."""

    def test_recursive_unmount(self, tmp_path):
        """Recursive unmount cleans up nested mounts."""
        _requires_root()

        base = tmp_path / "base"
        base.mkdir()
        sub = base / "sub"
        sub.mkdir()

        src1 = tmp_path / "src1"
        src1.mkdir()
        (src1 / "a.txt").write_text("a")
        src2 = tmp_path / "src2"
        src2.mkdir()
        (src2 / "b.txt").write_text("b")

        py_bind_mount(str(src1), str(base))
        # sub is now inside the bind mount — recreate it
        (base / "sub").mkdir(exist_ok=True)
        py_bind_mount(str(src2), str(base / "sub"))

        assert (base / "a.txt").read_text() == "a"
        assert (base / "sub" / "b.txt").read_text() == "b"

        py_umount_recursive_lazy(str(base))

        # After recursive unmount, mounts are gone.
        assert not (base / "a.txt").exists()

    def test_recursive_unmount_deep_nesting(self, tmp_path):
        """Recursive unmount handles 4 levels of nested mounts."""
        _requires_root()

        dirs = []
        for i in range(4):
            d = tmp_path / f"src{i}"
            d.mkdir()
            (d / f"level{i}.txt").write_text(str(i))
            dirs.append(d)

        base = tmp_path / "base"
        base.mkdir()

        # Mount level 0 at base
        py_bind_mount(str(dirs[0]), str(base))
        # Create nested dirs inside mount and mount deeper
        for i in range(1, 4):
            nested = base / "/".join(f"d{j}" for j in range(1, i + 1))
            nested.mkdir(parents=True, exist_ok=True)
            py_bind_mount(str(dirs[i]), str(nested))

        # Verify deepest level
        deep = base / "d1/d2/d3"
        assert (deep / "level3.txt").read_text() == "3"

        py_umount_recursive_lazy(str(base))

        # All mounts gone
        assert not (base / "level0.txt").exists()


# ================================================================== #
#  Namespace enter (preexec helpers)                                   #
# ================================================================== #


class TestNsenterPreexec:
    """Rootful nsenter preexec — enters mount namespace + chroot."""

    def test_rootful_popen_preexec(self, tmp_path):
        """py_nsenter_preexec works in a Popen preexec_fn."""
        _requires_root()

        # Create a sandbox-like environment: unshare mount+pid, chroot.
        rootfs = tmp_path / "rootfs"
        rootfs.mkdir()
        (rootfs / "bin").mkdir()
        # Use a static busybox or just test with /bin/sh from host
        # We'll create a minimal rootfs by bind-mounting /
        py_bind_mount("/", str(rootfs))
        try:
            # Start a process in a new mount namespace
            sentinel = subprocess.Popen(
                ["unshare", "--mount", "--fork", "--", "sleep", "infinity"],
                start_new_session=True,
            )
            time.sleep(0.3)  # Wait for namespace setup

            try:
                pid = sentinel.pid

                def _preexec():
                    py_nsenter_preexec(pid)

                proc = subprocess.Popen(
                    ["cat", "/etc/hostname"],
                    preexec_fn=_preexec,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                stdout, _ = proc.communicate(timeout=5)
                # Should succeed (can read /etc/hostname from target's mount ns)
                assert proc.returncode == 0
            finally:
                sentinel.kill()
                sentinel.wait()
        finally:
            py_umount_lazy(str(rootfs))


class TestNsenterErrors:
    """Error paths for nsenter preexec helpers."""

    def test_nsenter_dead_pid_raises(self):
        """nsenter_preexec with a dead process raises OSError."""
        _requires_root()
        # Fork and immediately reap so PID is gone.
        pid = os.fork()
        if pid == 0:
            os._exit(0)
        os.waitpid(pid, 0)

        with pytest.raises(OSError):
            py_nsenter_preexec(pid)

    def test_nsenter_invalid_pid_raises(self):
        """nsenter_preexec with a nonexistent PID raises OSError."""
        _requires_root()
        with pytest.raises(OSError):
            py_nsenter_preexec(999999999)

    def test_userns_preexec_invalid_pid_raises(self):
        """userns_preexec with a nonexistent PID raises OSError."""
        with pytest.raises(OSError):
            py_userns_preexec(999999999, "/", "/")


# ================================================================== #
#  fuser_kill — process killing via /proc walk                         #
# ================================================================== #


class TestFuserKill:
    """py_fuser_kill: kill processes holding open fds to a path."""

    def test_kills_holder(self, tmp_path):
        """Process holding an fd to a file gets killed."""
        target = tmp_path / "target_file"
        target.touch()

        # Fork a child that holds the file open.
        pid = os.fork()
        if pid == 0:
            # Child: open file, sleep forever.
            fd = os.open(str(target), os.O_RDONLY)
            try:
                time.sleep(300)
            except:
                pass
            os._exit(0)

        try:
            time.sleep(0.1)  # Let child open the file.

            killed = py_fuser_kill(str(target))
            assert killed >= 1

            # Verify child is dead by reaping it (waitpid).
            # os.kill(pid, 0) succeeds on zombies, so use waitpid instead.
            for _ in range(50):
                wpid, status = os.waitpid(pid, os.WNOHANG)
                if wpid != 0:
                    # Reaped — child is dead.
                    assert os.WIFSIGNALED(status)
                    assert os.WTERMSIG(status) == signal.SIGKILL
                    pid = 0  # Mark as reaped.
                    break
                time.sleep(0.05)
            else:
                pytest.fail("Child process not killed")
        finally:
            if pid:
                try:
                    os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
                except (ChildProcessError, ProcessLookupError):
                    pass

    def test_no_holders_returns_zero(self, tmp_path):
        """No processes holding the file → returns 0."""
        target = tmp_path / "lonely_file"
        target.touch()
        killed = py_fuser_kill(str(target))
        assert killed == 0

    def test_nonexistent_path_returns_zero(self):
        """Nonexistent path doesn't crash, returns 0."""
        killed = py_fuser_kill("/tmp/.nitrobox_nonexistent_fuser_test")
        assert killed == 0

    def test_kills_multiple_holders(self, tmp_path):
        """Multiple processes holding the same file all get killed."""
        target = tmp_path / "shared_file"
        target.touch()

        pids = []
        for _ in range(3):
            pid = os.fork()
            if pid == 0:
                fd = os.open(str(target), os.O_RDONLY)
                try:
                    time.sleep(300)
                except:
                    pass
                os._exit(0)
            pids.append(pid)

        try:
            time.sleep(0.2)  # Let all children open the file.

            killed = py_fuser_kill(str(target))
            assert killed >= 3

            # Reap all children.
            for pid in pids:
                for _ in range(50):
                    wpid, status = os.waitpid(pid, os.WNOHANG)
                    if wpid != 0:
                        break
                    time.sleep(0.05)
                else:
                    pytest.fail(f"Child {pid} not killed")
        finally:
            for pid in pids:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    pass

    def test_does_not_kill_self(self, tmp_path):
        """fuser_kill skips current process even if it holds the fd."""
        target = tmp_path / "self_test"
        target.touch()

        # Open the file in THIS process.
        fd = os.open(str(target), os.O_RDONLY)
        try:
            killed = py_fuser_kill(str(target))
            # Should NOT have killed us.
            assert killed == 0
        finally:
            os.close(fd)
