"""Tests for CRIU-based process checkpoint/restore.

Requires root and Docker (for rootfs preparation).
Run with: sudo python -m pytest tests/test_checkpoint.py -v
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time

import pytest

from nitrobox import Sandbox, SandboxConfig, CheckpointManager

TEST_IMAGE = os.environ.get("LITE_SANDBOX_TEST_IMAGE", "ubuntu:22.04")


def _requires_root():
    if os.geteuid() != 0:
        pytest.skip("requires root")


def _requires_docker():
    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        pytest.skip("requires Docker")


def _requires_criu():
    if not CheckpointManager.check_available():
        pytest.skip("CRIU not available")


@pytest.fixture
def sandbox(tmp_path, shared_cache_dir):
    _requires_root()
    _requires_docker()
    _requires_criu()
    config = SandboxConfig(
        image=TEST_IMAGE,
        working_dir="/workspace",
        env_base_dir=str(tmp_path / "envs"),
        rootfs_cache_dir=shared_cache_dir,
    )
    sb = Sandbox(config, name="ckpt-test")
    yield sb
    sb.delete()


@pytest.fixture
def ckpt_path(tmp_path):
    path = str(tmp_path / "checkpoint")
    yield path
    shutil.rmtree(path, ignore_errors=True)


class TestCheckpointSaveRestore:
    """Basic checkpoint save and restore."""

    def test_save_and_restore_file(self, sandbox, ckpt_path):
        """Filesystem state is restored after checkpoint."""
        sandbox.run("echo v1 > /workspace/data.txt")
        mgr = CheckpointManager(sandbox)
        mgr.save(ckpt_path)

        sandbox.run("echo v2 > /workspace/data.txt")
        out, _ = sandbox.run("cat /workspace/data.txt")
        assert "v2" in out

        mgr.restore(ckpt_path)
        out, ec = sandbox.run("cat /workspace/data.txt")
        assert ec == 0
        assert "v1" in out

    def test_restore_after_delete(self, sandbox, ckpt_path):
        """Restore works after files are deleted."""
        sandbox.run("echo data > /workspace/file.txt")
        sandbox.run("mkdir -p /workspace/subdir")
        sandbox.run("echo nested > /workspace/subdir/nested.txt")

        mgr = CheckpointManager(sandbox)
        mgr.save(ckpt_path)

        sandbox.run("rm -rf /workspace/*")
        out, _ = sandbox.run("ls /workspace/")
        assert out.strip() == ""

        mgr.restore(ckpt_path)
        out, _ = sandbox.run("cat /workspace/file.txt")
        assert "data" in out
        out, _ = sandbox.run("cat /workspace/subdir/nested.txt")
        assert "nested" in out

    def test_commands_work_after_restore(self, sandbox, ckpt_path):
        """Multiple commands succeed after restore."""
        sandbox.run("echo v1 > /workspace/test.txt")
        mgr = CheckpointManager(sandbox)
        mgr.save(ckpt_path)

        sandbox.run("echo v2 > /workspace/test.txt")
        mgr.restore(ckpt_path)

        for i in range(5):
            out, ec = sandbox.run(f"echo cmd_{i}")
            assert ec == 0
            assert f"cmd_{i}" in out

    def test_leave_running(self, sandbox, ckpt_path):
        """Sandbox keeps running after save with leave_running=True.

        Verifies the shell process is truly the SAME process (not
        restarted) by checking the persistent shell PID before and after.
        """
        sandbox.run("echo before > /workspace/test.txt")
        pid_before = sandbox._persistent_shell.pid
        mgr = CheckpointManager(sandbox)
        mgr.save(ckpt_path, leave_running=True)

        # Shell should be the SAME process (not restarted).
        pid_after = sandbox._persistent_shell.pid
        assert pid_before == pid_after, (
            f"Shell PID changed after save: {pid_before} -> {pid_after}"
        )

        # Commands should still work.
        out, ec = sandbox.run("echo alive")
        assert ec == 0
        assert "alive" in out

        # File state should be preserved.
        out, ec = sandbox.run("cat /workspace/test.txt")
        assert ec == 0
        assert "before" in out

        # Shell should still accept new commands.
        sandbox.run("echo after > /workspace/test.txt")
        out, _ = sandbox.run("cat /workspace/test.txt")
        assert "after" in out


class TestCheckpointEdgeCases:
    """Edge cases and error handling."""

    def test_save_duplicate_path_raises(self, sandbox, ckpt_path):
        mgr = CheckpointManager(sandbox)
        mgr.save(ckpt_path)
        with pytest.raises(FileExistsError):
            mgr.save(ckpt_path)

    def test_restore_nonexistent_raises(self, sandbox):
        mgr = CheckpointManager(sandbox)
        with pytest.raises(FileNotFoundError):
            mgr.restore("/tmp/nonexistent_checkpoint_path")

    def test_multiple_save_restore_cycles(self, sandbox, tmp_path):
        """Multiple checkpoint/restore cycles work."""
        mgr = CheckpointManager(sandbox)

        for i in range(3):
            ckpt = str(tmp_path / f"ckpt_{i}")
            sandbox.run(f"echo iter_{i} > /workspace/data.txt")
            mgr.save(ckpt)

        # Restore to first checkpoint
        mgr.restore(str(tmp_path / "ckpt_0"))
        out, _ = sandbox.run("cat /workspace/data.txt")
        assert "iter_0" in out

        # Restore to last checkpoint
        mgr.restore(str(tmp_path / "ckpt_2"))
        out, _ = sandbox.run("cat /workspace/data.txt")
        assert "iter_2" in out


class TestCheckpointPerformance:
    """Performance smoke tests (not strict)."""

    def test_save_latency(self, sandbox, ckpt_path):
        sandbox.run("echo data > /workspace/test.txt")
        mgr = CheckpointManager(sandbox)
        t0 = time.monotonic()
        mgr.save(ckpt_path)
        elapsed = time.monotonic() - t0
        print(f"CRIU save: {elapsed*1000:.0f}ms")
        assert elapsed < 10  # generous 10s limit for CI

    def test_restore_latency(self, sandbox, ckpt_path):
        sandbox.run("echo data > /workspace/test.txt")
        mgr = CheckpointManager(sandbox)
        mgr.save(ckpt_path)
        sandbox.run("echo v2 > /workspace/test.txt")

        t0 = time.monotonic()
        mgr.restore(ckpt_path)
        elapsed = time.monotonic() - t0
        print(f"CRIU restore: {elapsed*1000:.0f}ms")
        assert elapsed < 10  # generous 10s limit for CI
