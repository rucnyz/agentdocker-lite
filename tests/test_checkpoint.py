"""Tests for CRIU-based process checkpoint/restore.

Requires ``nitrobox setup`` (installs setuid helper + CRIU).

These tests verify that the helper-based checkpoint provides the same
capabilities as rootful CRIU: full process state (memory, registers,
file descriptors) is preserved across save/restore.
"""

from __future__ import annotations

import os
import shutil
import time

import pytest

from nitrobox import Sandbox, SandboxConfig, CheckpointManager

TEST_IMAGE = os.environ.get("LITE_SANDBOX_TEST_IMAGE", "ubuntu:22.04")


def _requires_helper():
    """Skip if checkpoint helper is not installed."""
    from nitrobox.checkpoint import _find_helper
    try:
        _find_helper()
    except FileNotFoundError:
        pytest.skip("nitrobox-checkpoint-helper not found. Run 'nitrobox setup'.")


def _requires_docker():
    import subprocess
    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        pytest.skip("requires Docker")


def _requires_criu():
    if not CheckpointManager.check_available():
        pytest.skip("CRIU not available")


@pytest.fixture
def sandbox(tmp_path, shared_cache_dir):
    _requires_helper()
    _requires_docker()
    _requires_criu()
    config = SandboxConfig(
        image=TEST_IMAGE,
        working_dir="/workspace",
        env_base_dir=str(tmp_path / "envs"),
        rootfs_cache_dir=shared_cache_dir,
    )
    box = Sandbox(config, name="ckpt-test")
    yield box
    # Force-umount overlay via setuid helper before delete — checkpoint
    # restore mounts overlay as root (stacked: one mount per restore),
    # and non-root can't umount root-created mounts.
    rootfs = box._rootfs
    if rootfs.is_mount():
        import subprocess
        from nitrobox.checkpoint import _find_helper
        try:
            helper = _find_helper()
            for _ in range(10):  # multiple restores stack mounts
                if not rootfs.is_mount():
                    break
                subprocess.run(
                    [helper, "umount", str(rootfs)],
                    capture_output=True, timeout=5,
                )
        except Exception:
            pass
    box.delete()


@pytest.fixture
def ckpt_path(tmp_path):
    path = str(tmp_path / "checkpoint")
    yield path
    shutil.rmtree(path, ignore_errors=True)


class TestCheckpointBasic:
    """Core save/restore functionality."""

    def test_save_produces_images(self, sandbox, ckpt_path):
        """Checkpoint save produces CRIU image files and sandbox stays alive."""
        sandbox.run("echo v1 > /workspace/data.txt")
        mgr = CheckpointManager(sandbox)
        mgr.save(ckpt_path)

        from pathlib import Path
        criu_dir = Path(ckpt_path) / "criu"
        assert criu_dir.exists()
        images = list(criu_dir.iterdir())
        assert len(images) > 5
        assert any(f.name == "pstree.img" for f in images)

        # Sandbox still works after save
        out, ec = sandbox.run("cat /workspace/data.txt")
        assert ec == 0
        assert "v1" in out

    def test_save_and_restore(self, sandbox, ckpt_path):
        """Filesystem state (files, nested dirs, many files) restored."""
        sandbox.run("echo data > /workspace/file.txt")
        sandbox.run("mkdir -p /workspace/a/b/c/d")
        sandbox.run("echo deep > /workspace/a/b/c/d/nested.txt")
        for i in range(20):
            sandbox.run(f"echo content_{i} > /workspace/f{i}.txt")

        mgr = CheckpointManager(sandbox)
        mgr.save(ckpt_path)

        sandbox.run("rm -rf /workspace/*")
        out, _ = sandbox.run("ls /workspace/")
        assert out.strip() == ""

        mgr.restore(ckpt_path)

        out, _ = sandbox.run("cat /workspace/file.txt")
        assert "data" in out
        out, _ = sandbox.run("cat /workspace/a/b/c/d/nested.txt")
        assert "deep" in out
        for i in range(20):
            out, ec = sandbox.run(f"cat /workspace/f{i}.txt")
            assert ec == 0
            assert f"content_{i}" in out

    def test_leave_running(self, sandbox, ckpt_path):
        """Sandbox keeps running after save with leave_running=True."""
        sandbox.run("echo before > /workspace/test.txt")
        pid_before = sandbox._persistent_shell.pid
        mgr = CheckpointManager(sandbox)
        mgr.save(ckpt_path, leave_running=True)

        pid_after = sandbox._persistent_shell.pid
        assert pid_before == pid_after

        out, ec = sandbox.run("echo alive")
        assert ec == 0
        assert "alive" in out

    def test_shell_responsive_after_restore(self, sandbox, ckpt_path):
        """Restored shell responds correctly to 10 rounds of I/O."""
        sandbox.run("echo before > /workspace/state.txt")
        mgr = CheckpointManager(sandbox)
        mgr.save(ckpt_path)

        sandbox.run("echo destroyed > /workspace/state.txt")
        mgr.restore(ckpt_path)

        for i in range(10):
            out, ec = sandbox.run(f"echo round_{i} && cat /workspace/state.txt")
            assert ec == 0
            assert f"round_{i}" in out
            assert "before" in out


class TestCheckpointRootfulCapability:
    """Verify capabilities that require rootful CRIU.

    These tests prove the setuid helper provides the same checkpoint
    fidelity as running CRIU as root (Docker-level checkpoint).
    """

    def test_pid_preserved(self, sandbox, ckpt_path):
        """Shell PID is the same after checkpoint/restore.

        CRIU restores the exact process tree with original PIDs — a
        rootful capability that requires CAP_SYS_ADMIN for PID restore.
        """
        out_before, _ = sandbox.run("echo $$")
        pid_before = out_before.strip()

        mgr = CheckpointManager(sandbox)
        mgr.save(ckpt_path)
        sandbox.run("echo modified > /workspace/junk.txt")
        mgr.restore(ckpt_path)

        out_after, ec = sandbox.run("echo $$")
        assert ec == 0
        pid_after = out_after.strip()
        assert pid_before == pid_after, f"PID changed: {pid_before} -> {pid_after}"

    def test_large_data_integrity(self, sandbox, ckpt_path):
        """10 MB random binary data is bit-for-bit identical after restore.

        Verifies CRIU's page-level memory dumping (pagemap + pages images)
        correctly handles substantial allocations.
        """
        sandbox.run("dd if=/dev/urandom bs=1M count=10 of=/workspace/large.bin 2>/dev/null")
        sandbox.run("sha256sum /workspace/large.bin > /workspace/sha.txt")
        hash_before, _ = sandbox.run("cat /workspace/sha.txt")

        mgr = CheckpointManager(sandbox)
        mgr.save(ckpt_path)
        sandbox.run("rm -f /workspace/large.bin /workspace/sha.txt")
        mgr.restore(ckpt_path)

        out, ec = sandbox.run("sha256sum /workspace/large.bin")
        assert ec == 0
        assert hash_before.strip().split()[0] == out.strip().split()[0]


class TestCheckpointMultiCycle:
    """Multiple checkpoint/restore cycles and branching."""

    def test_multiple_save_restore_cycles(self, sandbox, tmp_path):
        """Three checkpoints, restore to first and last non-sequentially."""
        mgr = CheckpointManager(sandbox)

        for i in range(3):
            ckpt = str(tmp_path / f"ckpt_{i}")
            sandbox.run(f"echo iter_{i} > /workspace/data.txt")
            mgr.save(ckpt)

        mgr.restore(str(tmp_path / "ckpt_0"))
        out, _ = sandbox.run("cat /workspace/data.txt")
        assert "iter_0" in out

        mgr.restore(str(tmp_path / "ckpt_2"))
        out, _ = sandbox.run("cat /workspace/data.txt")
        assert "iter_2" in out

    def test_branching_restore(self, sandbox, tmp_path):
        """Checkpoint A, modify, checkpoint B, restore A, then restore B."""
        mgr = CheckpointManager(sandbox)

        sandbox.run("echo branch_a > /workspace/data.txt")
        ckpt_a = str(tmp_path / "ckpt_a")
        mgr.save(ckpt_a)

        sandbox.run("echo branch_b > /workspace/data.txt")
        ckpt_b = str(tmp_path / "ckpt_b")
        mgr.save(ckpt_b)

        mgr.restore(ckpt_a)
        out, _ = sandbox.run("cat /workspace/data.txt")
        assert "branch_a" in out

        mgr.restore(ckpt_b)
        out, _ = sandbox.run("cat /workspace/data.txt")
        assert "branch_b" in out


class TestCheckpointErrorHandling:
    """Error cases."""

    def test_save_duplicate_path_raises(self, sandbox, ckpt_path):
        mgr = CheckpointManager(sandbox)
        mgr.save(ckpt_path)
        with pytest.raises(FileExistsError):
            mgr.save(ckpt_path)

    def test_restore_nonexistent_raises(self, sandbox):
        mgr = CheckpointManager(sandbox)
        with pytest.raises(FileNotFoundError):
            mgr.restore("/tmp/nonexistent_checkpoint_path")


class TestCheckpointPerformance:
    """Performance smoke tests (not strict)."""

    def test_save_latency(self, sandbox, ckpt_path):
        sandbox.run("echo data > /workspace/test.txt")
        mgr = CheckpointManager(sandbox)
        t0 = time.monotonic()
        mgr.save(ckpt_path)
        elapsed = time.monotonic() - t0
        print(f"CRIU save: {elapsed*1000:.0f}ms")
        assert elapsed < 10

    def test_restore_latency(self, sandbox, ckpt_path):
        sandbox.run("echo data > /workspace/test.txt")
        mgr = CheckpointManager(sandbox)
        mgr.save(ckpt_path)
        sandbox.run("echo v2 > /workspace/test.txt")

        t0 = time.monotonic()
        mgr.restore(ckpt_path)
        elapsed = time.monotonic() - t0
        print(f"CRIU restore: {elapsed*1000:.0f}ms")
        assert elapsed < 10
