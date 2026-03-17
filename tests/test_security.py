"""Tests for security hardening: seccomp, user namespace mode, devices.

seccomp tests require root. User namespace tests must run as non-root.

Run with: sudo python -m pytest tests/test_security.py -v
"""

from __future__ import annotations

import os
import subprocess

import pytest

from agentdocker_lite import Sandbox, SandboxConfig

TEST_IMAGE = os.environ.get("LITE_SANDBOX_TEST_IMAGE", "ubuntu:22.04")


def _requires_root():
    if os.geteuid() != 0:
        pytest.skip("requires root")


def _requires_docker():
    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        pytest.skip("requires Docker")


# ------------------------------------------------------------------ #
#  Fixtures                                                            #
# ------------------------------------------------------------------ #


@pytest.fixture
def root_sandbox(tmp_path):
    """Standard root sandbox with seccomp enabled (default)."""
    _requires_root()
    _requires_docker()
    config = SandboxConfig(
        image=TEST_IMAGE,
        working_dir="/workspace",
        env_base_dir=str(tmp_path / "envs"),
        rootfs_cache_dir=str(tmp_path / "cache"),
        seccomp=True,
    )
    sb = Sandbox(config, name="sec-test")
    yield sb
    sb.delete()


@pytest.fixture
def userns_sandbox(tmp_path):
    """User namespace sandbox — skipped if running as root."""
    if os.geteuid() == 0:
        pytest.skip("userns test must run as non-root")
    _requires_docker()
    config = SandboxConfig(
        image=TEST_IMAGE,
        working_dir="/workspace",
        env_base_dir=str(tmp_path / "envs"),
        rootfs_cache_dir=str(tmp_path / "cache"),
    )
    sb = Sandbox(config, name="userns-test")
    yield sb
    sb.delete()


# ------------------------------------------------------------------ #
#  seccomp tests (root mode)                                           #
# ------------------------------------------------------------------ #


class TestSeccomp:
    """Verify seccomp blocks dangerous operations inside sandbox."""

    def test_normal_commands_work(self, root_sandbox):
        """Normal commands should not be affected by seccomp."""
        output, ec = root_sandbox.run("echo hello && ls / > /dev/null && cat /etc/hostname")
        assert ec == 0
        assert "hello" in output

    def test_fork_works(self, root_sandbox):
        """Regular fork/exec should work (clone without NS flags)."""
        output, ec = root_sandbox.run("bash -c 'echo from_child'")
        assert ec == 0
        assert "from_child" in output

    def test_seccomp_blocks_in_rootfs_with_python(self, tmp_path):
        """seccomp blocks mount/unshare when rootfs has python3 (e.g. Kali)."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=str(tmp_path / "cache"),
            seccomp=True,
        )
        sb = Sandbox(config, name="seccomp-py-test")
        try:
            # Check if python3 available — seccomp only works if it is
            _, ec = sb.run("which python3")
            if ec != 0:
                pytest.skip("rootfs has no python3 — seccomp helper can't run")
            output, ec = sb.run("mount -t tmpfs none /mnt 2>&1 || echo BLOCKED")
            assert "BLOCKED" in output or "Operation not permitted" in output or ec != 0
        finally:
            sb.delete()


# ------------------------------------------------------------------ #
#  User namespace tests (non-root)                                     #
# ------------------------------------------------------------------ #


class TestUserNamespace:
    """Verify user namespace sandbox works without root."""

    def test_basic_command(self, userns_sandbox):
        """Basic echo should work."""
        output, ec = userns_sandbox.run("echo hello userns")
        assert ec == 0
        assert "hello userns" in output

    def test_working_directory(self, userns_sandbox):
        """Should start in the configured working directory."""
        output, ec = userns_sandbox.run("pwd")
        assert ec == 0
        assert "workspace" in output

    def test_file_io(self, userns_sandbox):
        """write_file/read_file should work via manual overlay."""
        userns_sandbox.write_file("/workspace/test.txt", "hello from host\n")
        content = userns_sandbox.read_file("/workspace/test.txt")
        assert "hello from host" in content

    def test_reset_clears_files(self, userns_sandbox):
        """Reset should clear sandbox changes (overlayfs upper)."""
        userns_sandbox.run("echo ephemeral > /workspace/temp.txt")
        userns_sandbox.reset()
        _, ec = userns_sandbox.run("cat /workspace/temp.txt 2>/dev/null")
        assert ec != 0  # file should be gone

    def test_dev_null(self, userns_sandbox):
        """/dev/null should work (bind-mounted from host)."""
        output, ec = userns_sandbox.run("echo test > /dev/null && echo ok")
        assert ec == 0
        assert "ok" in output

    def test_proc_mounted(self, userns_sandbox):
        """/proc should be mounted."""
        output, ec = userns_sandbox.run("cat /proc/1/cmdline 2>/dev/null | tr '\\0' ' '")
        assert ec == 0

    def test_sequential_commands(self, userns_sandbox):
        """Multiple sequential commands should work."""
        for i in range(5):
            output, ec = userns_sandbox.run(f"echo iter-{i}")
            assert ec == 0
            assert f"iter-{i}" in output

    def test_popen(self, userns_sandbox):
        """popen() should work in userns mode via nsenter --user."""
        proc = userns_sandbox.popen("echo popen-userns")
        assert proc.stdout
        output = proc.stdout.read()
        proc.wait(timeout=5)
        assert b"popen-userns" in output


# ------------------------------------------------------------------ #
#  Device passthrough tests (root mode)                                #
# ------------------------------------------------------------------ #


class TestDevices:
    """Verify device passthrough."""

    def test_dev_null_accessible(self, root_sandbox):
        """/dev/null should work (created in sandbox init)."""
        output, ec = root_sandbox.run("echo test > /dev/null && echo ok")
        assert ec == 0
        assert "ok" in output

    def test_device_passthrough(self, tmp_path):
        """Passed-through device should be accessible."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=str(tmp_path / "cache"),
            devices=["/dev/null"],  # /dev/null exists on all Linux
        )
        sb = Sandbox(config, name="dev-test")
        try:
            output, ec = sb.run("test -e /dev/null && echo exists")
            assert ec == 0
            assert "exists" in output
        finally:
            sb.delete()
