"""Tests for lite-sandbox.

These tests require root and Docker (for auto rootfs preparation).
Run with: sudo python -m pytest tests/ -v
"""

from __future__ import annotations

import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from lite_sandbox import Sandbox, SandboxConfig

# Use a pre-existing rootfs if available, otherwise fall back to Docker image.
# Set LITE_SANDBOX_TEST_IMAGE env var to override.
TEST_IMAGE = os.environ.get("LITE_SANDBOX_TEST_IMAGE", "ubuntu:22.04")


def _requires_root():
    if os.geteuid() != 0:
        pytest.skip("requires root")


def _requires_docker():
    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        pytest.skip("requires Docker")


@pytest.fixture
def sandbox(tmp_path):
    _requires_root()
    _requires_docker()
    config = SandboxConfig(
        image=TEST_IMAGE,
        working_dir="/workspace",
        env_base_dir=str(tmp_path / "envs"),
        rootfs_cache_dir=str(tmp_path / "cache"),
    )
    sb = Sandbox(config, name="test")
    yield sb
    sb.delete()


# ------------------------------------------------------------------ #
#  Basic lifecycle                                                     #
# ------------------------------------------------------------------ #


class TestLifecycle:
    def test_create_and_delete(self, tmp_path):
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=str(tmp_path / "cache"),
        )
        sb = Sandbox(config, name="lifecycle")
        assert sb.rootfs.exists()
        sb.delete()
        assert not (tmp_path / "envs" / "lifecycle").exists()

    def test_repr(self, sandbox):
        r = repr(sandbox)
        assert "test" in r
        assert "overlayfs" in r


# ------------------------------------------------------------------ #
#  Command execution                                                   #
# ------------------------------------------------------------------ #


class TestRun:
    def test_echo(self, sandbox):
        output, ec = sandbox.run("echo hello")
        assert ec == 0
        assert "hello" in output

    def test_exit_code(self, sandbox):
        _, ec = sandbox.run("false")
        assert ec != 0

    def test_multiline_output(self, sandbox):
        output, ec = sandbox.run("echo line1 && echo line2 && echo line3")
        assert ec == 0
        lines = [l for l in output.strip().split("\n") if l]
        assert len(lines) == 3

    def test_working_dir(self, sandbox):
        output, ec = sandbox.run("pwd")
        assert ec == 0
        assert "/workspace" in output

    def test_environment(self, tmp_path):
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            environment={"MY_VAR": "test_value_123"},
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=str(tmp_path / "cache"),
        )
        sb = Sandbox(config, name="env-test")
        output, ec = sb.run("echo $MY_VAR")
        assert ec == 0
        assert "test_value_123" in output
        sb.delete()

    def test_timeout(self, sandbox):
        output, ec = sandbox.run("sleep 60", timeout=1)
        assert ec == 124
        assert "timed out" in output.lower()

    def test_binary_output(self, sandbox):
        """Command output with non-UTF8 bytes should not crash."""
        output, ec = sandbox.run("printf '\\x80\\x81\\x82'")
        assert ec == 0
        assert len(output) > 0

    def test_special_chars_in_output(self, sandbox):
        """Output containing patterns that look like control sequences."""
        output, ec = sandbox.run("echo '__DONE_abc:0'")
        assert ec == 0
        assert "__DONE_abc:0" in output

    def test_large_output(self, sandbox):
        output, ec = sandbox.run("seq 1 10000")
        assert ec == 0
        lines = output.strip().split("\n")
        assert len(lines) == 10000

    def test_sequential_commands(self, sandbox):
        """Multiple commands execute correctly in sequence."""
        for i in range(10):
            output, ec = sandbox.run(f"echo {i}")
            assert ec == 0
            assert str(i) in output


# ------------------------------------------------------------------ #
#  File operations                                                     #
# ------------------------------------------------------------------ #


class TestFileOps:
    def test_write_and_read(self, sandbox):
        sandbox.write_file("/workspace/hello.txt", "world\n")
        content = sandbox.read_file("/workspace/hello.txt")
        assert content.strip() == "world"

    def test_write_bytes(self, sandbox):
        data = b"\x00\x01\x02\x03"
        sandbox.write_file("/workspace/binary.bin", data)
        host_path = sandbox.rootfs / "workspace" / "binary.bin"
        assert host_path.read_bytes() == data

    def test_copy_to_and_from(self, sandbox, tmp_path):
        src = tmp_path / "input.txt"
        src.write_text("copy test content")
        sandbox.copy_to(str(src), "/workspace/copied.txt")

        dst = tmp_path / "output.txt"
        sandbox.copy_from("/workspace/copied.txt", str(dst))
        assert dst.read_text() == "copy test content"

    def test_read_nonexistent_raises(self, sandbox):
        with pytest.raises(FileNotFoundError):
            sandbox.read_file("/nonexistent/file.txt")

    def test_copy_from_nonexistent_raises(self, sandbox, tmp_path):
        with pytest.raises(FileNotFoundError):
            sandbox.copy_from("/nonexistent", str(tmp_path / "out"))

    def test_file_visible_via_run(self, sandbox):
        sandbox.write_file("/workspace/via_api.txt", "from api\n")
        output, ec = sandbox.run("cat /workspace/via_api.txt")
        assert ec == 0
        assert "from api" in output


# ------------------------------------------------------------------ #
#  Reset                                                               #
# ------------------------------------------------------------------ #


class TestReset:
    def test_reset_clears_files(self, sandbox):
        sandbox.run("touch /workspace/ephemeral.txt")
        output, ec = sandbox.run("ls /workspace/ephemeral.txt")
        assert ec == 0

        sandbox.reset()

        _, ec = sandbox.run("ls /workspace/ephemeral.txt 2>/dev/null")
        assert ec != 0

    def test_reset_preserves_base(self, sandbox):
        """Base image files survive reset."""
        sandbox.reset()
        output, ec = sandbox.run("ls /bin/sh")
        assert ec == 0

    def test_multiple_resets(self, sandbox):
        for i in range(5):
            sandbox.run(f"echo {i} > /workspace/counter.txt")
            sandbox.reset()
            _, ec = sandbox.run("test -f /workspace/counter.txt")
            assert ec != 0, f"File survived reset #{i}"

    def test_commands_work_after_reset(self, sandbox):
        sandbox.reset()
        output, ec = sandbox.run("echo post-reset")
        assert ec == 0
        assert "post-reset" in output


# ------------------------------------------------------------------ #
#  Concurrency                                                         #
# ------------------------------------------------------------------ #


class TestConcurrency:
    def test_parallel_sandboxes(self, tmp_path):
        _requires_root()
        _requires_docker()
        n = 4

        def run_worker(i):
            config = SandboxConfig(
                image=TEST_IMAGE,
                working_dir="/workspace",
                env_base_dir=str(tmp_path / "envs"),
                rootfs_cache_dir=str(tmp_path / "cache"),
            )
            sb = Sandbox(config, name=f"parallel-{i}")
            output, ec = sb.run(f"echo worker-{i}")
            sb.delete()
            return output.strip(), ec

        with ThreadPoolExecutor(max_workers=n) as pool:
            results = list(pool.map(run_worker, range(n)))

        for i, (output, ec) in enumerate(results):
            assert ec == 0
            assert f"worker-{i}" in output


# ------------------------------------------------------------------ #
#  Performance (smoke test, not strict)                                #
# ------------------------------------------------------------------ #


class TestPerformance:
    def test_command_latency(self, sandbox):
        """Command latency should be well under 500ms."""
        times = []
        for _ in range(20):
            t0 = time.monotonic()
            sandbox.run("true")
            times.append((time.monotonic() - t0) * 1000)

        median = sorted(times)[len(times) // 2]
        assert median < 500, f"Median command latency {median:.1f}ms > 500ms"

    def test_reset_latency(self, sandbox):
        """Reset should complete in under 500ms."""
        times = []
        for _ in range(5):
            sandbox.run("dd if=/dev/zero of=/workspace/junk bs=1M count=1 2>/dev/null")
            t0 = time.monotonic()
            sandbox.reset()
            times.append((time.monotonic() - t0) * 1000)

        median = sorted(times)[len(times) // 2]
        assert median < 500, f"Median reset latency {median:.1f}ms > 500ms"


# ------------------------------------------------------------------ #
#  PTY mode                                                            #
# ------------------------------------------------------------------ #


@pytest.fixture
def tty_sandbox(tmp_path):
    _requires_root()
    _requires_docker()
    config = SandboxConfig(
        image=TEST_IMAGE,
        working_dir="/workspace",
        tty=True,
        env_base_dir=str(tmp_path / "envs"),
        rootfs_cache_dir=str(tmp_path / "cache"),
    )
    sb = Sandbox(config, name="tty-test")
    yield sb
    sb.delete()


class TestPTY:
    def test_basic_command(self, tty_sandbox):
        """PTY mode should execute commands like pipe mode."""
        output, ec = tty_sandbox.run("echo hello-pty")
        assert ec == 0
        assert "hello-pty" in output

    def test_exit_code(self, tty_sandbox):
        _, ec = tty_sandbox.run("false")
        assert ec != 0

    def test_isatty(self, tty_sandbox):
        """Programs should see a TTY."""
        output, ec = tty_sandbox.run("python3 -c 'import sys; print(sys.stdout.isatty())'")
        assert ec == 0
        assert "True" in output

    def test_sequential(self, tty_sandbox):
        for i in range(5):
            output, ec = tty_sandbox.run(f"echo {i}")
            assert ec == 0
            assert str(i) in output

    def test_write_stdin_requires_tty(self, sandbox):
        """write_stdin on non-tty sandbox should raise."""
        with pytest.raises(RuntimeError, match="tty"):
            sandbox.write_stdin("hello\n")

    def test_reset_works(self, tty_sandbox):
        tty_sandbox.run("touch /workspace/gone.txt")
        tty_sandbox.reset()
        _, ec = tty_sandbox.run("test -f /workspace/gone.txt")
        assert ec != 0
        # Shell still works after reset
        output, ec = tty_sandbox.run("echo post-reset")
        assert ec == 0
        assert "post-reset" in output


# ------------------------------------------------------------------ #
#  Background processes                                                #
# ------------------------------------------------------------------ #


class TestBackground:
    def test_run_and_check(self, sandbox):
        handle = sandbox.run_background("for i in 1 2 3; do echo line$i; sleep 0.1; done")
        time.sleep(1)
        output, running = sandbox.check_background(handle)
        assert "line1" in output
        assert "line3" in output
        assert not running  # should have finished

    def test_long_running(self, sandbox):
        handle = sandbox.run_background("sleep 60")
        time.sleep(0.5)
        _, running = sandbox.check_background(handle)
        assert running
        final = sandbox.stop_background(handle)
        assert isinstance(final, str)
        # Process should be dead now
        assert handle not in sandbox._bg_handles

    def test_run_while_background(self, sandbox):
        """Regular run() should work while a background process is active."""
        handle = sandbox.run_background("sleep 60")
        time.sleep(0.2)
        output, ec = sandbox.run("echo foreground")
        assert ec == 0
        assert "foreground" in output
        sandbox.stop_background(handle)

    def test_reset_clears_background(self, sandbox):
        handle = sandbox.run_background("sleep 60")
        sandbox.reset()
        assert handle not in sandbox._bg_handles


# ------------------------------------------------------------------ #
#  Network isolation                                                   #
# ------------------------------------------------------------------ #


class TestNetIsolate:
    def test_loopback_only(self, tmp_path):
        """With net_isolate, only loopback should exist."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            net_isolate=True,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=str(tmp_path / "cache"),
        )
        sb = Sandbox(config, name="net-test")
        output, ec = sb.run("ip link show 2>/dev/null || cat /proc/net/dev")
        assert ec == 0
        # Should NOT have eth0 or any real interface
        assert "eth0" not in output
        sb.delete()

    def test_no_net_isolate_default(self, sandbox):
        """Default sandbox should see host interfaces."""
        output, ec = sandbox.run("ip link show 2>/dev/null || cat /proc/net/dev")
        assert ec == 0
        # Should see more than just loopback
        lines = output.strip().split("\n")
        assert len(lines) > 1
