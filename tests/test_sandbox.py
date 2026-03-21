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
        time.sleep(0.5)
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


# ------------------------------------------------------------------ #
#  mount_overlay (new mount API + legacy fallback)                     #
# ------------------------------------------------------------------ #


class TestMountOverlay:
    def test_single_layer(self, tmp_path):
        """mount_overlay works with a single lowerdir."""
        _requires_root()
        from agentdocker_lite._mount import mount_overlay

        lower = tmp_path / "lower"
        lower.mkdir()
        (lower / "hello.txt").write_text("hello")
        upper = tmp_path / "upper"
        upper.mkdir()
        work = tmp_path / "work"
        work.mkdir()
        merged = tmp_path / "merged"
        merged.mkdir()

        mount_overlay(str(lower), str(upper), str(work), str(merged))
        assert (merged / "hello.txt").read_text() == "hello"
        subprocess.run(["umount", str(merged)], capture_output=True)

    def test_multi_layer(self, tmp_path):
        """mount_overlay works with multiple lowerdirs (bypasses 256-byte limit)."""
        _requires_root()
        from agentdocker_lite._mount import mount_overlay

        # Create 6 layers — this exceeds the 256-byte fsconfig limit
        layers = []
        for i in range(6):
            d = tmp_path / f"layer_{i:03d}_padding_for_length"
            d.mkdir()
            (d / f"file_{i}.txt").write_text(f"layer {i}")
            layers.append(d)

        upper = tmp_path / "upper"
        upper.mkdir()
        work = tmp_path / "work"
        work.mkdir()
        merged = tmp_path / "merged"
        merged.mkdir()

        lowerdir = ":".join(str(d) for d in reversed(layers))
        assert len(lowerdir) > 256, "lowerdir must exceed fsconfig limit"

        mount_overlay(lowerdir, str(upper), str(work), str(merged))

        # All layer files should be visible
        for i in range(6):
            assert (merged / f"file_{i}.txt").read_text() == f"layer {i}"

        subprocess.run(["umount", str(merged)], capture_output=True)

    def test_new_api_detection(self):
        """_check_new_mount_api returns a boolean (True on kernel >= 6.8)."""
        _requires_root()
        from agentdocker_lite._mount import _check_new_mount_api

        result = _check_new_mount_api()
        assert isinstance(result, bool)


# ------------------------------------------------------------------ #
#  Port mapping (pasta networking)                                      #
# ------------------------------------------------------------------ #


def _requires_tun():
    if not os.path.exists("/dev/net/tun"):
        pytest.skip("requires /dev/net/tun (pasta networking)")


class TestPortMap:
    def test_port_mapping(self, tmp_path):
        """port_map forwards host port to sandbox server."""
        _requires_root()
        _requires_docker()
        _requires_tun()
        import urllib.request

        config = SandboxConfig(
            image="python:3.11-slim",
            working_dir="/tmp",
            net_isolate=True,
            port_map=["19876:8000"],
            seccomp=False,
            env_base_dir=str(tmp_path / "envs"),
        )
        sb = Sandbox(config, name="port-test")
        try:
            sb.run_background("python3 -m http.server 8000 --directory /tmp")

            # Poll until server is ready (instead of fixed sleep)
            # Use 127.0.0.1: pasta accepts IPv6 connections but can't
            # forward them to an IPv4-only server (known pasta bug,
            # https://bugs.passt.top/show_bug.cgi?id=131)
            for _ in range(20):
                try:
                    resp = urllib.request.urlopen("http://127.0.0.1:19876/", timeout=1)
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                raise AssertionError("server did not start")
            assert resp.status == 200
        finally:
            sb.delete()

    def test_internal_loopback(self, tmp_path):
        """Loopback is automatically brought up inside net-isolated sandbox."""
        _requires_root()
        _requires_tun()
        _requires_docker()

        config = SandboxConfig(
            image="python:3.11-slim",
            working_dir="/tmp",
            net_isolate=True,
            port_map=["19877:8000"],
            seccomp=False,
            env_base_dir=str(tmp_path / "envs"),
        )
        sb = Sandbox(config, name="lo-test")
        try:
            sb.run_background("python3 -m http.server 8000 --directory /tmp")
            time.sleep(0.3)

            sb.write_file("/tmp/lo_check.py",
                "import urllib.request\n"
                "r = urllib.request.urlopen('http://127.0.0.1:8000/')\n"
                "print(r.status)\n"
            )
            output, ec = sb.run("python3 /tmp/lo_check.py")
            assert ec == 0
            assert "200" in output
        finally:
            sb.delete()


# ------------------------------------------------------------------ #
#  Layer cache                                                          #
# ------------------------------------------------------------------ #


class TestLayerCache:
    def test_shared_layers(self, tmp_path):
        """Two images sharing base layers reuse cached layers."""
        _requires_root()
        _requires_docker()

        cache_dir = tmp_path / "cache"
        configs = []
        sandboxes = []
        for i, img in enumerate(["python:3.11-slim", "python:3.12-slim"]):
            config = SandboxConfig(
                image=img,
                working_dir="/tmp",
                env_base_dir=str(tmp_path / "envs"),
                rootfs_cache_dir=str(cache_dir),
            )
            sb = Sandbox(config, name=f"layer-test-{i}")
            configs.append(config)
            sandboxes.append(sb)

        try:
            layers0 = set(l.name for l in (sandboxes[0]._layer_dirs or []))
            layers1 = set(l.name for l in (sandboxes[1]._layer_dirs or []))
            shared = layers0 & layers1
            assert len(shared) > 0, "python:3.11 and 3.12 should share base layers"

            # Both should work
            out0, _ = sandboxes[0].run("python3 --version")
            out1, _ = sandboxes[1].run("python3 --version")
            assert "3.11" in out0
            assert "3.12" in out1
        finally:
            for sb in sandboxes:
                sb.delete()

    def test_multi_layer_image(self, tmp_path):
        """An image with many layers mounts and works correctly."""
        _requires_root()
        _requires_docker()

        config = SandboxConfig(
            image="python:3.11-slim",  # 4 layers
            working_dir="/tmp",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=str(tmp_path / "cache"),
        )
        sb = Sandbox(config, name="multi-layer")
        try:
            assert sb._layer_dirs is not None
            assert len(sb._layer_dirs) >= 4

            output, ec = sb.run("python3 -c 'print(1+1)'")
            assert ec == 0
            assert "2" in output

            # Reset should work with multi-layer
            sb.run("touch /tmp/marker")
            sb.reset()
            output, ec = sb.run("test -f /tmp/marker && echo yes || echo no")
            assert "no" in output
        finally:
            sb.delete()


# ------------------------------------------------------------------ #
#  Seccomp clone3 → ENOSYS (threading must work)                       #
# ------------------------------------------------------------------ #


class TestClone3Fallback:
    def test_threading_works_with_seccomp(self, tmp_path):
        """clone3 returns ENOSYS so glibc falls back to clone(2), allowing threads."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image="python:3.11-slim",
            working_dir="/tmp",
            seccomp=True,  # seccomp ON — clone3 should get ENOSYS
            env_base_dir=str(tmp_path / "envs"),
        )
        sb = Sandbox(config, name="clone3-test")
        try:
            # Python threading uses clone/clone3 under the hood
            output, ec = sb.run(
                "python3 -c '"
                "import threading; "
                "r = []; "
                "t = threading.Thread(target=lambda: r.append(42)); "
                "t.start(); t.join(); "
                "print(r[0])'"
            )
            assert ec == 0
            assert "42" in output
        finally:
            sb.delete()


# ------------------------------------------------------------------ #
#  Hostname configuration                                              #
# ------------------------------------------------------------------ #


class TestHostname:
    def test_custom_hostname(self, tmp_path):
        """hostname= sets the UTS hostname inside the sandbox."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/",
            hostname="my-sandbox",
            net_isolate=True,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=str(tmp_path / "cache"),
        )
        sb = Sandbox(config, name="hostname-test")
        try:
            output, ec = sb.run("hostname")
            assert ec == 0
            assert "my-sandbox" in output.strip()
        finally:
            sb.delete()


# ------------------------------------------------------------------ #
#  Read-only root filesystem                                           #
# ------------------------------------------------------------------ #


class TestReadOnly:
    def test_read_only_rootfs(self, tmp_path):
        """read_only=True makes root filesystem read-only."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/",
            read_only=True,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=str(tmp_path / "cache"),
        )
        sb = Sandbox(config, name="ro-test")
        try:
            # Writes to rootfs should fail
            _, ec = sb.run("touch /test_file 2>/dev/null")
            assert ec != 0
            # Reads should work
            output, ec = sb.run("cat /etc/hostname 2>/dev/null || echo ok")
            assert ec == 0
        finally:
            sb.delete()

    def test_read_only_without_seccomp(self, tmp_path):
        """read_only works even when seccomp is disabled."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/",
            read_only=True,
            seccomp=False,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=str(tmp_path / "cache"),
        )
        sb = Sandbox(config, name="ro-nosec")
        try:
            _, ec = sb.run("touch /test_file 2>/dev/null")
            assert ec != 0
        finally:
            sb.delete()


# ------------------------------------------------------------------ #
#  get_image_config                                                    #
# ------------------------------------------------------------------ #


class TestGetImageConfig:
    def test_basic(self):
        """get_image_config returns cmd, entrypoint, env, working_dir."""
        _requires_docker()
        from agentdocker_lite import get_image_config
        cfg = get_image_config("python:3.11-slim")
        assert cfg is not None
        assert cfg["cmd"] == ["python3"]
        assert "PATH" in cfg["env"]
        assert isinstance(cfg["exposed_ports"], list)

    def test_nonexistent_image(self):
        """get_image_config returns None for missing image."""
        from agentdocker_lite import get_image_config
        assert get_image_config("nonexistent:image-xyz") is None


# ------------------------------------------------------------------ #
#  Background process cleanup on delete                                #
# ------------------------------------------------------------------ #


class TestDeleteCleansBackground:
    def test_delete_kills_background(self, tmp_path):
        """delete() should kill background processes before unmounting."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=str(tmp_path / "cache"),
        )
        sb = Sandbox(config, name="bg-cleanup")
        sb.run_background("sleep 3600")
        sb.run_background("sleep 3600")
        # delete should not leave mount points behind
        sb.delete()
        rootfs = tmp_path / "envs" / "bg-cleanup" / "rootfs"
        assert not rootfs.exists() or not os.path.ismount(str(rootfs))

