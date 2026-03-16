"""Tests for agentdocker-lite.

These tests require root and Docker (for auto rootfs preparation).
Run with: sudo python -m pytest tests/ -v
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import pytest

from agentdocker_lite import Sandbox, SandboxConfig

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
        lines = [line for line in output.strip().split("\n") if line]
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
        n = 2  # CI runners have limited resources

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
        _, ec = tty_sandbox.run("test -t 1")
        assert ec == 0

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
        assert handle not in sandbox.list_background()

    def test_list_background(self, sandbox):
        h1 = sandbox.run_background("sleep 60")
        h2 = sandbox.run_background("sleep 60")
        time.sleep(0.3)
        procs = sandbox.list_background()
        assert h1 in procs and procs[h1]["running"]
        assert h2 in procs and procs[h2]["running"]
        sandbox.stop_background(h1)
        sandbox.stop_background(h2)

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
        assert handle not in sandbox.list_background()


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


# ------------------------------------------------------------------ #
#  Popen                                                               #
# ------------------------------------------------------------------ #


class TestPopen:
    def test_basic_popen(self, sandbox):
        proc = sandbox.popen("echo popen_test")
        line = proc.stdout.readline()
        assert b"popen_test" in line
        proc.wait()

    def test_popen_stdin(self, sandbox):
        proc = sandbox.popen("bash")
        proc.stdin.write(b"echo from_stdin\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
        assert b"from_stdin" in line
        proc.terminate()

    def test_popen_exit_code(self, sandbox):
        proc = sandbox.popen("exit 42")
        assert proc.wait() == 42


# ------------------------------------------------------------------ #
#  Filesystem snapshots                                                #
# ------------------------------------------------------------------ #


class TestFsSnapshot:
    def test_save_and_restore(self, sandbox, tmp_path):
        sandbox.run("echo v1 > /workspace/data.txt")
        ckpt = str(tmp_path / "snap")
        sandbox.fs_snapshot(ckpt)

        sandbox.run("echo v2 > /workspace/data.txt")
        sandbox.fs_restore(ckpt)

        output, ec = sandbox.run("cat /workspace/data.txt")
        assert ec == 0
        assert "v1" in output

    def test_restore_nonexistent_raises(self, sandbox):
        with pytest.raises(FileNotFoundError):
            sandbox.fs_restore("/tmp/nonexistent_snapshot")

    def test_reset_after_restore(self, sandbox, tmp_path):
        """reset() returns to clean image, not to snapshot."""
        sandbox.run("echo snap > /workspace/data.txt")
        ckpt = str(tmp_path / "snap")
        sandbox.fs_snapshot(ckpt)
        sandbox.fs_restore(ckpt)

        sandbox.reset()
        output, ec = sandbox.run("cat /workspace/data.txt 2>&1")
        assert ec != 0  # file gone after reset


class TestSaveAsImage:
    """Test save_as_image: export sandbox state as a Docker image."""

    IMAGE_TAG = "adl-test-save:cached"

    def test_save_and_load(self, sandbox):
        sandbox.run("echo cached_data > /workspace/cached.txt")
        sandbox.save_as_image(self.IMAGE_TAG)

        try:
            sb2 = Sandbox(SandboxConfig(image=self.IMAGE_TAG, working_dir="/workspace"), name="from-cache")
            out, ec = sb2.run("cat /workspace/cached.txt")
            assert ec == 0
            assert "cached_data" in out
            sb2.delete()
        finally:
            subprocess.run(["docker", "rmi", "-f", self.IMAGE_TAG], capture_output=True)


# ------------------------------------------------------------------ #
#  Volumes                                                             #
# ------------------------------------------------------------------ #


class TestVolumes:
    def test_ro_volume(self, tmp_path):
        _requires_root()
        _requires_docker()
        host_dir = tmp_path / "host_data"
        host_dir.mkdir()
        (host_dir / "file.txt").write_text("host_content")

        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=str(tmp_path / "cache"),
            volumes=[f"{host_dir}:/mnt/data:ro"],
        )
        sb = Sandbox(config, name="vol-ro")
        try:
            output, ec = sb.run("cat /mnt/data/file.txt")
            assert ec == 0
            assert "host_content" in output

            # Write should fail
            _, ec = sb.run("touch /mnt/data/new_file 2>&1")
            assert ec != 0
        finally:
            sb.delete()

    def test_rw_volume(self, tmp_path):
        _requires_root()
        _requires_docker()
        host_dir = tmp_path / "host_rw"
        host_dir.mkdir()

        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=str(tmp_path / "cache"),
            volumes=[f"{host_dir}:/mnt/data:rw"],
        )
        sb = Sandbox(config, name="vol-rw")
        try:
            sb.run("echo written_from_sandbox > /mnt/data/output.txt")
            assert (host_dir / "output.txt").read_text().strip() == "written_from_sandbox"
        finally:
            sb.delete()


# ------------------------------------------------------------------ #
#  Features, pressure, reclaim                                         #
# ------------------------------------------------------------------ #


class TestObservability:
    def test_features_dict(self, sandbox):
        assert isinstance(sandbox.features, dict)
        assert "seccomp" in sandbox.features
        assert "mask_paths" in sandbox.features
        assert "cap_drop" in sandbox.features

    def test_pressure(self, tmp_path):
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=str(tmp_path / "cache"),
            cpu_max="50000 100000",
        )
        sb = Sandbox(config, name="psi-test")
        try:
            psi = sb.pressure()
            assert isinstance(psi, dict)
            if psi:  # cgroup v2 available
                assert "cpu" in psi
                assert "avg10" in psi["cpu"]
        finally:
            sb.delete()

    def test_reclaim_memory(self, sandbox):
        sandbox.run("echo hello")
        result = sandbox.reclaim_memory()
        # Should return bool, True if pidfd + process_madvise available
        assert isinstance(result, bool)


# ------------------------------------------------------------------ #
#  Filesystem isolation                                                #
# ------------------------------------------------------------------ #


class TestFsIsolation:
    def test_sandbox_cannot_modify_base_rootfs(self, sandbox):
        """Writes inside the sandbox must not leak through to the base rootfs."""
        sandbox.run("echo 'hacked' > /etc/MARKER_FILE_TEST")
        # Verify the file exists inside the sandbox
        output, ec = sandbox.run("cat /etc/MARKER_FILE_TEST")
        assert ec == 0
        assert "hacked" in output
        # Base rootfs must NOT have this file
        base_marker = sandbox._base_rootfs / "etc" / "MARKER_FILE_TEST"
        assert not base_marker.exists()

    def test_two_sandboxes_isolated(self, tmp_path):
        """Two sandboxes sharing the same image have independent filesystems."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=str(tmp_path / "cache"),
        )
        sb1 = Sandbox(config, name="iso-1")
        sb2 = Sandbox(config, name="iso-2")

        sb1.run("echo 'from-sb1' > /tmp/marker.txt")
        _, ec = sb2.run("cat /tmp/marker.txt 2>/dev/null")
        assert ec != 0  # sb2 must not see sb1's file

        sb1.delete()
        sb2.delete()

    def test_reset_restores_deleted_base_files(self, sandbox):
        """Deleting a base-image file then resetting should restore it."""
        # /bin/ls is part of the base image
        _, ec = sandbox.run("ls /bin/ls")
        assert ec == 0

        sandbox.run("rm -f /bin/ls")
        _, ec = sandbox.run("ls /bin/ls 2>/dev/null")
        assert ec != 0  # ls is gone

        sandbox.reset()
        _, ec = sandbox.run("ls /bin/ls")
        assert ec == 0  # restored after reset

    def test_modified_base_file_restored_on_reset(self, sandbox):
        """Modifying a base-image file then resetting should revert changes."""
        original, ec = sandbox.run("cat /etc/hostname 2>/dev/null || echo __none__")
        assert ec == 0

        sandbox.run("echo 'tampered' > /etc/hostname")
        modified, _ = sandbox.run("cat /etc/hostname")
        assert "tampered" in modified

        sandbox.reset()
        restored, _ = sandbox.run("cat /etc/hostname 2>/dev/null || echo __none__")
        assert restored.strip() == original.strip()


# ------------------------------------------------------------------ #
#  Process / PID namespace isolation                                   #
# ------------------------------------------------------------------ #


class TestPidIsolation:
    def test_pid_1_is_not_host_init(self, sandbox):
        """PID 1 inside the sandbox should be the sandbox shell, not host init."""
        output, ec = sandbox.run("cat /proc/1/cmdline 2>/dev/null | tr '\\0' ' '")
        assert ec == 0
        # PID 1 should be unshare/bash, not systemd/init
        assert "systemd" not in output

    def test_sandbox_sees_limited_pids(self, sandbox):
        """The sandbox should see far fewer processes than the host."""
        output, ec = sandbox.run("ls /proc | grep -E '^[0-9]+$' | wc -l")
        assert ec == 0
        sandbox_pids = int(output.strip())
        # A fresh sandbox should have very few PIDs (shell + ls + wc pipeline)
        assert sandbox_pids < 20

    def test_shell_state_not_leaked_between_commands(self, sandbox):
        """Each command runs in a sub-shell; env vars don't leak across runs."""
        sandbox.run("export SECRET_VAR=s3cret_12345")
        output, ec = sandbox.run("echo $SECRET_VAR")
        assert ec == 0
        assert "s3cret_12345" not in output


# ------------------------------------------------------------------ #
#  cgroup v2 resource limits                                           #
# ------------------------------------------------------------------ #


def _cgroup_v2_available():
    return Path("/sys/fs/cgroup/cgroup.controllers").exists()


class TestResourceLimits:
    def test_memory_limit_enforced(self, tmp_path):
        """A process exceeding memory_max should be killed or fail to allocate."""
        _requires_root()
        _requires_docker()
        if not _cgroup_v2_available():
            pytest.skip("cgroup v2 not available")

        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            memory_max="16777216",  # 16 MB
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=str(tmp_path / "cache"),
        )
        sb = Sandbox(config, name="mem-limit")
        # Try to allocate 100 MB -- should fail or be killed
        _, ec = sb.run(
            "python3 -c 'x = bytearray(100*1024*1024)' 2>&1",
            timeout=10,
        )
        assert ec != 0
        sb.delete()

    def test_pids_limit_enforced(self, tmp_path):
        """pids_max should be correctly written to the cgroup."""
        _requires_root()
        _requires_docker()
        if not _cgroup_v2_available():
            pytest.skip("cgroup v2 not available")

        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            pids_max="42",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=str(tmp_path / "cache"),
        )
        sb = Sandbox(config, name="pid-limit")
        # Verify cgroup pids.max is set correctly from the host side
        cgroup_path = sb._cgroup_path
        assert cgroup_path is not None, "cgroup was not created"
        pids_max_value = (cgroup_path / "pids.max").read_text().strip()
        assert pids_max_value == "42", f"Expected pids.max=42, got {pids_max_value}"
        # Verify sandbox is still functional
        output, ec = sb.run("echo pids-ok")
        assert ec == 0
        assert "pids-ok" in output
        sb.delete()

    def test_cpu_max_accepted(self, tmp_path):
        """cpu_max config should not cause errors during sandbox creation."""
        _requires_root()
        _requires_docker()
        if not _cgroup_v2_available():
            pytest.skip("cgroup v2 not available")

        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            cpu_max="50000 100000",  # 50% of one CPU
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=str(tmp_path / "cache"),
        )
        sb = Sandbox(config, name="cpu-limit")
        output, ec = sb.run("echo cpu-ok")
        assert ec == 0
        assert "cpu-ok" in output
        sb.delete()


# ------------------------------------------------------------------ #
#  Edge cases and robustness                                           #
# ------------------------------------------------------------------ #


class TestEdgeCases:
    def test_empty_command(self, sandbox):
        """Empty command should not hang or crash."""
        output, ec = sandbox.run("")
        assert ec == 0

    def test_very_long_command(self, sandbox):
        """A command with a very large argument should work."""
        long_arg = "A" * 100_000
        output, ec = sandbox.run(f"echo {long_arg}")
        assert ec == 0
        assert long_arg in output

    def test_command_with_embedded_newlines(self, sandbox):
        """Multiline shell script passed as a single command."""
        output, ec = sandbox.run("echo line1\necho line2\necho line3")
        assert ec == 0
        assert "line1" in output

    def test_rapid_run_reset_cycles(self, sandbox):
        """Simulate an RL training loop: many run-reset cycles."""
        for i in range(50):
            output, ec = sandbox.run(
                f"echo step-{i} && touch /workspace/file-{i}.txt"
            )
            assert ec == 0, f"Failed at step {i}"
            assert f"step-{i}" in output
            sandbox.reset()

    def test_command_list_form(self, sandbox):
        """run() accepts a list of arguments as well as a string."""
        output, ec = sandbox.run(["echo", "hello", "world"])
        assert ec == 0
        assert "hello world" in output

    def test_run_after_delete(self, tmp_path):
        """Running a command after delete should fail gracefully."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=str(tmp_path / "cache"),
        )
        sb = Sandbox(config, name="dead-sandbox")
        sb.delete()
        # rootfs is gone, so run() should raise (shell can't restart)
        with pytest.raises((RuntimeError, OSError)):
            sb.run("echo hello")

    def test_concurrent_commands_on_same_sandbox(self, sandbox):
        """Multiple threads issuing commands to one sandbox should serialize."""

        def worker(i):
            output, ec = sandbox.run(f"echo {i}")
            return i, output.strip(), ec

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(worker, range(20)))

        for i, output, ec in results:
            assert ec == 0
            assert str(i) in output

    def test_stderr_captured(self, sandbox):
        """stderr output should be captured alongside stdout."""
        output, ec = sandbox.run("echo out; echo err >&2")
        assert ec == 0
        assert "out" in output
        assert "err" in output

