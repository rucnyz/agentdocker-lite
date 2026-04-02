"""Tests for nitrobox.

These tests require root and Docker (for auto rootfs preparation).
Run with: sudo python -m pytest tests/ -v
"""

from __future__ import annotations

import os
import subprocess
import time
import urllib.error
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import pytest

from nitrobox import Sandbox, SandboxConfig

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
def sandbox(tmp_path, shared_cache_dir):
    _requires_root()
    _requires_docker()
    config = SandboxConfig(
        image=TEST_IMAGE,
        working_dir="/workspace",
        env_base_dir=str(tmp_path / "envs"),
        rootfs_cache_dir=shared_cache_dir,
    )
    sb = Sandbox(config, name="test")
    yield sb
    sb.delete()


# ------------------------------------------------------------------ #
#  Basic lifecycle                                                     #
# ------------------------------------------------------------------ #


class TestLifecycle:
    def test_create_and_delete(self, tmp_path, shared_cache_dir):
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
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

    def test_environment(self, tmp_path, shared_cache_dir):
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            environment={"MY_VAR": "test_value_123"},
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
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

    def test_many_files_reset(self, sandbox):
        """Reset with many files (RL episode scenario)."""
        sandbox.run("mkdir -p /workspace/src && seq 1 200 | "
                    "xargs -I{} sh -c 'echo x > /workspace/src/gen_{}.py'")
        sandbox.reset()
        _, ec = sandbox.run("ls /workspace/src/ 2>/dev/null")
        assert ec != 0, "directory survived reset"
        out, ec = sandbox.run("echo ok")
        assert ec == 0 and "ok" in out

    def test_delete_cleans_dead_dirs(self, tmp_path, shared_cache_dir):
        """delete() removes all dead dirs left by rename-based reset."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="dead-dir-test")
        env_dir = tmp_path / "envs" / "dead-dir-test"

        for _ in range(5):
            sb.run("seq 1 50 | xargs -I{} touch /workspace/f_{}")
            sb.reset()

        sb.delete()
        assert not env_dir.exists(), "env_dir not cleaned up by delete()"


# ------------------------------------------------------------------ #
#  Concurrency                                                         #
# ------------------------------------------------------------------ #


class TestConcurrency:
    def test_parallel_sandboxes(self, tmp_path, shared_cache_dir):
        _requires_root()
        _requires_docker()
        n = 2  # CI runners have limited resources

        def run_worker(i):
            config = SandboxConfig(
                image=TEST_IMAGE,
                working_dir="/workspace",
                env_base_dir=str(tmp_path / "envs"),
                rootfs_cache_dir=shared_cache_dir,
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
def tty_sandbox(tmp_path, shared_cache_dir):
    _requires_root()
    _requires_docker()
    config = SandboxConfig(
        image=TEST_IMAGE,
        working_dir="/workspace",
        tty=True,
        env_base_dir=str(tmp_path / "envs"),
        rootfs_cache_dir=shared_cache_dir,
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
    def test_loopback_only(self, tmp_path, shared_cache_dir):
        """With net_isolate, only loopback should exist."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            net_isolate=True,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
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

    IMAGE_TAG = "nbx-test-save:cached"

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
    def test_ro_volume(self, tmp_path, shared_cache_dir):
        _requires_root()
        _requires_docker()
        host_dir = tmp_path / "host_data"
        host_dir.mkdir()
        (host_dir / "file.txt").write_text("host_content")

        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
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

    def test_rw_volume(self, tmp_path, shared_cache_dir):
        _requires_root()
        _requires_docker()
        host_dir = tmp_path / "host_rw"
        host_dir.mkdir()

        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
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

    def test_pressure(self, tmp_path, shared_cache_dir):
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
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

    def test_two_sandboxes_isolated(self, tmp_path, shared_cache_dir):
        """Two sandboxes sharing the same image have independent filesystems."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
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
    def test_memory_limit_enforced(self, tmp_path, shared_cache_dir):
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
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="mem-limit")
        # Try to allocate 100 MB -- should fail or be killed
        _, ec = sb.run(
            "python3 -c 'x = bytearray(100*1024*1024)' 2>&1",
            timeout=10,
        )
        assert ec != 0
        sb.delete()

    def test_pids_limit_enforced(self, tmp_path, shared_cache_dir):
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
            rootfs_cache_dir=shared_cache_dir,
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

    def test_cpu_max_accepted(self, tmp_path, shared_cache_dir):
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
            rootfs_cache_dir=shared_cache_dir,
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

    def test_run_after_delete(self, tmp_path, shared_cache_dir):
        """Running a command after delete should fail gracefully."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="dead-sandbox")
        sb.delete()
        # rootfs is gone, so run() should raise (shell can't restart)
        from nitrobox._errors import SandboxError
        with pytest.raises((RuntimeError, OSError, SandboxError)):
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
        from nitrobox._core import py_mount_overlay as mount_overlay

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
        from nitrobox._core import py_mount_overlay as mount_overlay

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
        from nitrobox._core import py_check_new_mount_api as _check_new_mount_api

        result = _check_new_mount_api()
        assert isinstance(result, bool)


# ------------------------------------------------------------------ #
#  Port mapping (pasta networking)                                      #
# ------------------------------------------------------------------ #


def _requires_tun():
    if not os.path.exists("/dev/net/tun"):
        pytest.skip("requires /dev/net/tun (pasta networking)")


class TestPortMap:
    def test_port_mapping(self, tmp_path, shared_cache_dir):
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
            rootfs_cache_dir=shared_cache_dir,
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

    def test_internal_loopback(self, tmp_path, shared_cache_dir):
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
            rootfs_cache_dir=shared_cache_dir,
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

    def test_delete_cleans_netns_rootful(self, tmp_path, shared_cache_dir):
        """delete() with port_map leaves no stale netns bind mounts (rootful)."""
        _requires_root()
        _requires_tun()
        _requires_docker()

        config = SandboxConfig(
            image=TEST_IMAGE,
            net_isolate=True,
            port_map=["19878:8000"],
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="netns-cleanup")
        env_dir = sb._env_dir
        sb.delete()

        # env_dir should be gone
        assert not env_dir.exists(), f"env_dir not cleaned: {list(env_dir.iterdir()) if env_dir.exists() else 'N/A'}"
        # No /run/netns bind mount left
        import subprocess
        mounts = subprocess.run(["mount"], capture_output=True, text=True).stdout
        assert "netns-cleanup" not in mounts, f"stale netns mount: {[l for l in mounts.splitlines() if 'netns-cleanup' in l]}"

    def test_delete_cleans_netns_userns(self, tmp_path, shared_cache_dir):
        """delete() with port_map leaves no stale .netns bind mounts (userns)."""
        if os.geteuid() == 0:
            pytest.skip("userns test must run as non-root")
        _requires_docker()

        config = SandboxConfig(
            image=TEST_IMAGE,
            net_isolate=True,
            port_map=["19878:8000"],
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="netns-cleanup-u")
        env_dir = sb._env_dir
        sb.delete()

        # env_dir should be gone (no stuck .netns bind mount)
        assert not env_dir.exists(), f"env_dir not cleaned: {list(env_dir.iterdir()) if env_dir.exists() else 'N/A'}"


# ------------------------------------------------------------------ #
#  Cleanup verification                                                 #
# ------------------------------------------------------------------ #


class TestCleanupVerification:
    """Verify that delete() and reset() leave no resource leaks."""

    def test_delete_removes_all_files(self, tmp_path, shared_cache_dir):
        """delete() removes the entire env_dir, no leftovers."""
        _requires_root()
        _requires_docker()

        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="clean-test")
        # Create some files inside sandbox
        sb.run("echo test > /workspace/file.txt")
        sb.run("mkdir -p /workspace/subdir && echo nested > /workspace/subdir/a.txt")
        env_dir = sb._env_dir
        sb.delete()

        assert not env_dir.exists(), \
            f"env_dir still exists after delete: {list(env_dir.rglob('*')) if env_dir.exists() else []}"

    def test_delete_kills_shell_process(self, tmp_path, shared_cache_dir):
        """delete() kills the persistent shell process — no zombies."""
        _requires_root()
        _requires_docker()

        config = SandboxConfig(
            image=TEST_IMAGE,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="proc-clean")
        shell_pid = sb._persistent_shell.pid
        assert shell_pid is not None

        sb.delete()

        # Process should be dead
        import signal
        with pytest.raises(ProcessLookupError):
            os.kill(shell_pid, signal.SIG_DFL)

    def test_reset_no_mount_leak(self, tmp_path, shared_cache_dir):
        """Multiple resets don't accumulate bind mounts."""
        _requires_root()
        _requires_docker()

        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="mount-leak")
        try:
            import subprocess
            before = subprocess.run(["mount"], capture_output=True, text=True).stdout.count("mount-leak")
            for _ in range(5):
                sb.reset()
            after = subprocess.run(["mount"], capture_output=True, text=True).stdout.count("mount-leak")
            # Mount count should not grow with resets
            assert after <= before + 2, \
                f"Mount leak: {before} mounts before, {after} after 5 resets"
        finally:
            sb.delete()

    def test_delete_no_stale_cgroup(self, tmp_path, shared_cache_dir):
        """delete() removes the cgroup directory."""
        _requires_root()
        _requires_docker()

        config = SandboxConfig(
            image=TEST_IMAGE,
            memory_max="256m",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="cg-clean")
        cgroup_path = sb._cgroup_path
        sb.delete()

        if cgroup_path:
            assert not cgroup_path.exists(), f"cgroup not cleaned: {cgroup_path}"


# ------------------------------------------------------------------ #
#  Layer cache                                                          #
# ------------------------------------------------------------------ #


class TestLayerCache:
    def test_shared_layers(self, tmp_path, shared_cache_dir):
        """Two images sharing base layers reuse cached layers."""
        _requires_root()
        _requires_docker()

        cache_dir = Path(shared_cache_dir)
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

    def test_multi_layer_image(self, tmp_path, shared_cache_dir):
        """An image with many layers mounts and works correctly."""
        _requires_root()
        _requires_docker()

        config = SandboxConfig(
            image="python:3.11-slim",  # 4 layers
            working_dir="/tmp",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
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
    def test_threading_works_with_seccomp(self, tmp_path, shared_cache_dir):
        """clone3 returns ENOSYS so glibc falls back to clone(2), allowing threads."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image="python:3.11-slim",
            working_dir="/tmp",
            seccomp=True,  # seccomp ON — clone3 should get ENOSYS
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
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
    def test_custom_hostname(self, tmp_path, shared_cache_dir):
        """hostname= sets the UTS hostname inside the sandbox."""
        _requires_root()
        _requires_docker()
        # CI containers may have /proc/sys/kernel/hostname read-only and
        # may lack the hostname binary; skip if neither method works.
        import subprocess
        r = subprocess.run(
            ["unshare", "--uts", "bash", "-c",
             "echo test > /proc/sys/kernel/hostname 2>/dev/null || hostname test 2>/dev/null"],
            capture_output=True,
        )
        if r.returncode != 0:
            pytest.skip("UTS namespace hostname write not permitted (CI container)")
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/",
            hostname="my-sandbox",
            net_isolate=True,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="hostname-test")
        try:
            output, ec = sb.run("hostname")
            assert ec == 0
            assert "my-sandbox" in output.strip()
        finally:
            sb.delete()


class TestDnsReset:
    """Verify DNS config persists after reset."""

    def test_dns_survives_reset(self, tmp_path, shared_cache_dir):
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            dns=["8.8.8.8", "1.1.1.1"],
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="dns-reset-test")
        try:
            sb.reset()
            output, ec = sb.run("cat /etc/resolv.conf")
            assert ec == 0
            assert "8.8.8.8" in output, "dns config lost after reset"
            assert "1.1.1.1" in output
        finally:
            sb.delete()


# ------------------------------------------------------------------ #
#  Read-only root filesystem                                           #
# ------------------------------------------------------------------ #


class TestReadOnly:
    def test_read_only_rootfs(self, tmp_path, shared_cache_dir):
        """read_only=True makes root filesystem read-only."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/",
            read_only=True,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
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

    def test_read_only_survives_reset(self, tmp_path, shared_cache_dir):
        """read_only is preserved after reset()."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/",
            read_only=True,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="ro-reset")
        try:
            _, ec = sb.run("touch /test_file 2>/dev/null")
            assert ec != 0
            sb.reset()
            _, ec = sb.run("touch /test_file 2>/dev/null")
            assert ec != 0
        finally:
            sb.delete()

    def test_read_only_without_seccomp(self, tmp_path, shared_cache_dir):
        """read_only works even when seccomp is disabled."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/",
            read_only=True,
            seccomp=False,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
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


class TestParseCpuMax:
    """Unit tests for _parse_cpu_max sugar."""

    def test_fraction(self):
        from nitrobox.config import _parse_cpu_max
        assert _parse_cpu_max("0.5") == "50000 100000"

    def test_integer_cores(self):
        from nitrobox.config import _parse_cpu_max
        assert _parse_cpu_max("2") == "200000 100000"

    def test_percentage(self):
        from nitrobox.config import _parse_cpu_max
        assert _parse_cpu_max("50%") == "50000 100000"

    def test_passthrough_raw(self):
        from nitrobox.config import _parse_cpu_max
        assert _parse_cpu_max("50000 100000") == "50000 100000"

    def test_small_fraction(self):
        from nitrobox.config import _parse_cpu_max
        result = _parse_cpu_max("0.01")
        quota, period = result.split()
        assert int(quota) >= 1
        assert period == "100000"

    def test_config_applies(self):
        """SandboxConfig.__post_init__ converts friendly cpu_max."""
        cfg = SandboxConfig(image="x", cpu_max="0.5")
        assert cfg.cpu_max == "50000 100000"


class TestParseIoMax:
    """Unit tests for _parse_io_max sugar."""

    def test_bare_size(self):
        from nitrobox.config import _parse_io_max
        # /dev/xxx won't resolve on CI, but MAJ:MIN passthrough works
        result = _parse_io_max("259:0 10mb")
        assert result == "259:0 wbps=10485760"

    def test_keyed_size(self):
        from nitrobox.config import _parse_io_max
        result = _parse_io_max("259:0 wbps=10mb")
        assert result == "259:0 wbps=10485760"

    def test_multiple_params(self):
        from nitrobox.config import _parse_io_max
        result = _parse_io_max("259:0 rbps=5mb wbps=10mb")
        assert "rbps=5242880" in result
        assert "wbps=10485760" in result

    def test_passthrough_raw(self):
        from nitrobox.config import _parse_io_max
        raw = "259:0 wbps=10485760"
        assert _parse_io_max(raw) == raw

    def test_config_applies(self):
        """SandboxConfig.__post_init__ converts friendly io_max."""
        cfg = SandboxConfig(image="x", io_max="259:0 10mb")
        assert cfg.io_max == "259:0 wbps=10485760"


class TestCpuShares:
    """Unit tests for _convert_cpu_shares."""

    def test_default_1024(self):
        from nitrobox.config import _convert_cpu_shares
        # Docker 1024 → cgroup v2 weight ~39 (formula: 1 + (1022*9999)/262142)
        assert 1 <= _convert_cpu_shares(1024) <= 10000

    def test_minimum(self):
        from nitrobox.config import _convert_cpu_shares
        assert _convert_cpu_shares(2) >= 1

    def test_maximum(self):
        from nitrobox.config import _convert_cpu_shares
        assert _convert_cpu_shares(262144) == 10000

    def test_from_docker(self):
        cfg = SandboxConfig.from_docker("img", cpu_shares=512)
        assert cfg.cpu_shares == 512

    def test_from_docker_run(self):
        cfg = SandboxConfig.from_docker_run("docker run --cpu-shares=2048 ubuntu")
        assert cfg.cpu_shares == 2048


class TestShmSize:
    """Unit tests for shm_size parsing."""

    def test_parse_human_readable(self):
        cfg = SandboxConfig(image="x", shm_size="256m")
        assert cfg.shm_size == str(256 * 1024**2)

    def test_from_docker(self):
        cfg = SandboxConfig.from_docker("img", shm_size="2g")
        assert cfg.shm_size == str(2 * 1024**3)

    def test_from_docker_run(self):
        cfg = SandboxConfig.from_docker_run("docker run --shm-size=512m ubuntu")
        assert cfg.shm_size == str(512 * 1024**2)


class TestMemorySwap:
    """Unit tests for memory_swap Docker→cgroup v2 conversion."""

    def test_unlimited(self):
        cfg = SandboxConfig(image="x", memory_swap="-1")
        assert cfg.memory_swap == "max"

    def test_zero_means_unset(self):
        """Docker: memory_swap=0 is treated as unset."""
        cfg = SandboxConfig(image="x", memory_swap="0")
        assert cfg.memory_swap is None

    def test_docker_semantics(self):
        """memory_swap=1g with memory_max=512m → swap=512m."""
        cfg = SandboxConfig(image="x", memory_max="512m", memory_swap="1g")
        expected_swap = 1024**3 - 512 * 1024**2
        assert cfg.memory_swap == str(expected_swap)

    def test_from_docker(self):
        cfg = SandboxConfig.from_docker("img", mem_limit="512m", memswap_limit="1g")
        expected_swap = 1024**3 - 512 * 1024**2
        assert cfg.memory_swap == str(expected_swap)

    def test_from_docker_run(self):
        cfg = SandboxConfig.from_docker_run(
            "docker run -m 512m --memory-swap=1g ubuntu"
        )
        expected_swap = 1024**3 - 512 * 1024**2
        assert cfg.memory_swap == str(expected_swap)


class TestTmpfs:
    """Unit tests for tmpfs parsing."""

    def test_from_docker_dict(self):
        cfg = SandboxConfig.from_docker("img", tmpfs={"/run": "size=100m"})
        assert cfg.tmpfs == ["/run:size=100m"]

    def test_from_docker_run(self):
        cfg = SandboxConfig.from_docker_run(
            "docker run --tmpfs /run:size=100m --tmpfs /tmp ubuntu"
        )
        assert "/run:size=100m" in cfg.tmpfs
        assert "/tmp" in cfg.tmpfs

    def test_config_direct(self):
        cfg = SandboxConfig(image="x", tmpfs=["/run:size=50m"])
        assert cfg.tmpfs == ["/run:size=50m"]


class TestCapAdd:
    """Unit tests for cap_add."""

    def test_from_docker(self):
        cfg = SandboxConfig.from_docker("img", cap_add=["SYS_PTRACE", "NET_ADMIN"])
        assert cfg.cap_add == ["SYS_PTRACE", "NET_ADMIN"]

    def test_from_docker_run(self):
        cfg = SandboxConfig.from_docker_run(
            "docker run --cap-add SYS_ADMIN --cap-add NET_RAW ubuntu"
        )
        assert "SYS_ADMIN" in cfg.cap_add
        assert "NET_RAW" in cfg.cap_add

    def test_sys_admin_disables_seccomp(self):
        cfg = SandboxConfig(image="x", cap_add=["SYS_ADMIN"])
        assert cfg.seccomp is False

    def test_no_cap_keeps_seccomp(self):
        cfg = SandboxConfig(image="x", cap_add=["NET_ADMIN"])
        assert cfg.seccomp is True


class TestUlimits:
    """Unit tests for ulimits."""

    def test_from_docker_dict(self):
        cfg = SandboxConfig.from_docker("img", ulimits={
            "nofile": {"soft": 65536, "hard": 65536},
            "nproc": {"soft": 4096, "hard": 8192},
        })
        assert cfg.ulimits["nofile"] == (65536, 65536)
        assert cfg.ulimits["nproc"] == (4096, 8192)

    def test_from_docker_int(self):
        cfg = SandboxConfig.from_docker("img", ulimits={"nofile": 65536})
        assert cfg.ulimits["nofile"] == (65536, 65536)

    def test_from_docker_run(self):
        cfg = SandboxConfig.from_docker_run(
            "docker run --ulimit nofile=65536:65536 --ulimit nproc=4096 ubuntu"
        )
        assert cfg.ulimits["nofile"] == (65536, 65536)
        assert cfg.ulimits["nproc"] == (4096, 4096)

    def test_config_direct(self):
        cfg = SandboxConfig(image="x", ulimits={"nofile": (1024, 2048)})
        assert cfg.ulimits["nofile"] == (1024, 2048)


class TestApplyImageDefaults:
    """Unit tests for _apply_image_defaults (image config backfill)."""

    def test_backfill_workdir(self, monkeypatch):
        from nitrobox.sandbox import _apply_image_defaults
        monkeypatch.setattr(
            "nitrobox.rootfs.get_image_config",
            lambda _img: {"working_dir": "/app", "env": {}, "cmd": None,
                          "entrypoint": None, "exposed_ports": []},
        )
        cfg = SandboxConfig(image="myimg")
        _apply_image_defaults(cfg)
        assert cfg.working_dir == "/app"

    def test_user_workdir_wins(self, monkeypatch):
        from nitrobox.sandbox import _apply_image_defaults
        monkeypatch.setattr(
            "nitrobox.rootfs.get_image_config",
            lambda _img: {"working_dir": "/app", "env": {}, "cmd": None,
                          "entrypoint": None, "exposed_ports": []},
        )
        cfg = SandboxConfig(image="myimg", working_dir="/custom")
        _apply_image_defaults(cfg)
        assert cfg.working_dir == "/custom"

    def test_backfill_env(self, monkeypatch):
        from nitrobox.sandbox import _apply_image_defaults
        monkeypatch.setattr(
            "nitrobox.rootfs.get_image_config",
            lambda _img: {"working_dir": None, "env": {"A": "1", "B": "2"},
                          "cmd": None, "entrypoint": None, "exposed_ports": []},
        )
        cfg = SandboxConfig(image="myimg", environment={"B": "override"})
        _apply_image_defaults(cfg)
        assert cfg.environment["A"] == "1"
        assert cfg.environment["B"] == "override"

    def test_no_image_config(self, monkeypatch):
        from nitrobox.sandbox import _apply_image_defaults
        monkeypatch.setattr(
            "nitrobox.rootfs.get_image_config",
            lambda _img: None,
        )
        cfg = SandboxConfig(image="myimg")
        _apply_image_defaults(cfg)
        assert cfg.working_dir == "/"
        assert cfg.environment == {}

    def test_no_image(self):
        from nitrobox.sandbox import _apply_image_defaults
        cfg = SandboxConfig()
        _apply_image_defaults(cfg)
        assert cfg.working_dir == "/"


class TestFromDocker:
    """Unit tests for SandboxConfig.from_docker()."""

    def test_basic(self):
        cfg = SandboxConfig.from_docker("ubuntu:22.04", cpus=0.5, mem_limit="512m")
        assert cfg.image == "ubuntu:22.04"
        assert cfg.cpu_max == "50000 100000"
        assert cfg.memory_max == str(512 * 1024**2)

    def test_volumes_dict(self):
        cfg = SandboxConfig.from_docker("img", volumes={
            "/host": {"bind": "/container", "mode": "ro"},
        })
        assert cfg.volumes == ["/host:/container:ro"]

    def test_volumes_list(self):
        cfg = SandboxConfig.from_docker("img", volumes=["/a:/b:rw"])
        assert cfg.volumes == ["/a:/b:rw"]

    def test_ports_dict(self):
        cfg = SandboxConfig.from_docker("img", ports={"80/tcp": 8080, "443/tcp": 8443})
        assert "8080:80" in cfg.port_map
        assert "8443:443" in cfg.port_map

    def test_ports_multi(self):
        cfg = SandboxConfig.from_docker("img", ports={"80/tcp": [8080, 9090]})
        assert "8080:80" in cfg.port_map
        assert "9090:80" in cfg.port_map

    def test_env_dict(self):
        cfg = SandboxConfig.from_docker("img", environment={"A": "1"})
        assert cfg.environment == {"A": "1"}

    def test_env_list(self):
        cfg = SandboxConfig.from_docker("img", environment=["A=1", "B=2"])
        assert cfg.environment == {"A": "1", "B": "2"}

    def test_network_none(self):
        cfg = SandboxConfig.from_docker("img", network_mode="none")
        assert cfg.net_isolate is True

    def test_hostname_dns(self):
        cfg = SandboxConfig.from_docker("img", hostname="web", dns=["8.8.8.8"])
        assert cfg.hostname == "web"
        assert cfg.dns == ["8.8.8.8"]

    def test_devices(self):
        cfg = SandboxConfig.from_docker("img", devices=["/dev/kvm:/dev/kvm:rwm"])
        assert cfg.devices == ["/dev/kvm"]

    def test_read_only(self):
        cfg = SandboxConfig.from_docker("img", read_only=True)
        assert cfg.read_only is True

    def test_privileged_disables_seccomp_and_grants_all_caps(self):
        cfg = SandboxConfig.from_docker("img", privileged=True)
        assert cfg.seccomp is False
        assert len(cfg.cap_add) > 30  # all caps
        assert "SYS_ADMIN" in cfg.cap_add
        assert "NET_RAW" in cfg.cap_add

    def test_pids_limit(self):
        cfg = SandboxConfig.from_docker("img", pids_limit=256)
        assert cfg.pids_max == "256"

    def test_ignored_params_no_error(self):
        cfg = SandboxConfig.from_docker("img", detach=True, remove=True,
                                        labels={"k": "v"}, name="foo")
        assert cfg.image == "img"

    def test_full_combo(self):
        """Docker SDK style with many params at once."""
        cfg = SandboxConfig.from_docker(
            "python:3.11-slim",
            cpus=2, mem_limit="1g", pids_limit=512,
            volumes={"/data": {"bind": "/data", "mode": "ro"}},
            ports={"80/tcp": 8080},
            environment={"APP_ENV": "prod"},
            hostname="worker",
            dns=["8.8.8.8", "1.1.1.1"],
            read_only=True,
            working_dir="/app",
        )
        assert cfg.image == "python:3.11-slim"
        assert cfg.cpu_max == "200000 100000"
        assert cfg.memory_max == str(1024**3)
        assert cfg.pids_max == "512"
        assert cfg.volumes == ["/data:/data:ro"]
        assert cfg.port_map == ["8080:80"]
        assert cfg.environment == {"APP_ENV": "prod"}
        assert cfg.hostname == "worker"
        assert cfg.dns == ["8.8.8.8", "1.1.1.1"]
        assert cfg.read_only is True
        assert cfg.working_dir == "/app"


class TestFromDockerRun:
    """Unit tests for SandboxConfig.from_docker_run()."""

    def test_basic(self):
        cfg = SandboxConfig.from_docker_run("docker run --cpus=0.5 -m 512m ubuntu:22.04")
        assert cfg.image == "ubuntu:22.04"
        assert cfg.cpu_max == "50000 100000"
        assert cfg.memory_max == str(512 * 1024**2)

    def test_volumes_and_ports(self):
        cfg = SandboxConfig.from_docker_run(
            "docker run -v /data:/data:ro -p 8080:80 nginx"
        )
        assert cfg.volumes == ["/data:/data:ro"]
        assert cfg.port_map == ["8080:80"]

    def test_env_and_hostname(self):
        cfg = SandboxConfig.from_docker_run(
            "docker run -e APP=prod -h worker python:3.11"
        )
        assert cfg.environment == {"APP": "prod"}
        assert cfg.hostname == "worker"

    def test_workdir_and_readonly(self):
        cfg = SandboxConfig.from_docker_run(
            "docker run -w /app --read-only ubuntu"
        )
        assert cfg.working_dir == "/app"
        assert cfg.read_only is True

    def test_network_none(self):
        cfg = SandboxConfig.from_docker_run("docker run --network none alpine")
        assert cfg.net_isolate is True

    def test_dns_and_device(self):
        cfg = SandboxConfig.from_docker_run(
            "docker run --dns 8.8.8.8 --device /dev/kvm:/dev/kvm:rwm ubuntu"
        )
        assert cfg.dns == ["8.8.8.8"]
        assert cfg.devices == ["/dev/kvm"]

    def test_strips_sudo_and_flags(self):
        cfg = SandboxConfig.from_docker_run("sudo docker run -d --rm -it ubuntu bash")
        assert cfg.image == "ubuntu"

    def test_long_form_flags(self):
        cfg = SandboxConfig.from_docker_run(
            "docker run --memory=1g --hostname=web --workdir=/srv nginx:latest"
        )
        assert cfg.memory_max == str(1024**3)
        assert cfg.hostname == "web"
        assert cfg.working_dir == "/srv"
        assert cfg.image == "nginx:latest"

    def test_no_image_raises(self):
        with pytest.raises(ValueError, match="No image found"):
            SandboxConfig.from_docker_run("docker run -d")

    def test_full_combo(self):
        cfg = SandboxConfig.from_docker_run(
            "docker run --cpus=2 -m 1g --pids-limit 512 "
            "-v /data:/data:ro -p 8080:80 -e APP_ENV=prod "
            "--hostname worker --dns 8.8.8.8 --read-only "
            "-w /app python:3.11-slim"
        )
        assert cfg.image == "python:3.11-slim"
        assert cfg.cpu_max == "200000 100000"
        assert cfg.memory_max == str(1024**3)
        assert cfg.pids_max == "512"
        assert cfg.volumes == ["/data:/data:ro"]
        assert cfg.port_map == ["8080:80"]
        assert cfg.environment == {"APP_ENV": "prod"}
        assert cfg.hostname == "worker"
        assert cfg.dns == ["8.8.8.8"]
        assert cfg.read_only is True
        assert cfg.working_dir == "/app"

    def test_privileged_grants_all_caps(self):
        cfg = SandboxConfig.from_docker_run("docker run --privileged ubuntu")
        assert cfg.seccomp is False
        assert len(cfg.cap_add) > 30
        assert "SYS_ADMIN" in cfg.cap_add

    def test_oom_score_adj(self):
        cfg = SandboxConfig.from_docker_run("docker run --oom-score-adj=500 ubuntu")
        assert cfg.oom_score_adj == 500

    def test_security_opt_seccomp_unconfined(self):
        cfg = SandboxConfig.from_docker_run(
            "docker run --security-opt seccomp=unconfined ubuntu"
        )
        assert cfg.seccomp is False

    def test_env_file(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("DB_HOST=localhost\nDB_PORT=5432\n# comment\n")
        cfg = SandboxConfig.from_docker_run(
            f"docker run --env-file {env_file} ubuntu"
        )
        assert cfg.environment["DB_HOST"] == "localhost"
        assert cfg.environment["DB_PORT"] == "5432"


class TestGetImageConfig:
    def test_basic(self):
        """get_image_config returns cmd, entrypoint, env, working_dir."""
        _requires_docker()
        from nitrobox import get_image_config
        cfg = get_image_config("python:3.11-slim")
        assert cfg is not None
        assert cfg["cmd"] == ["python3"]
        assert "PATH" in cfg["env"]
        assert isinstance(cfg["exposed_ports"], list)

    def test_nonexistent_image(self):
        """get_image_config returns None for missing image."""
        from nitrobox import get_image_config
        assert get_image_config("nonexistent:image-xyz") is None


# ------------------------------------------------------------------ #
#  Background process cleanup on delete                                #
# ------------------------------------------------------------------ #


class TestDeleteCleansBackground:
    def test_delete_kills_background(self, tmp_path, shared_cache_dir):
        """delete() should kill background processes before unmounting."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="bg-cleanup")
        sb.run_background("sleep 3600")
        sb.run_background("sleep 3600")
        # delete should not leave mount points behind
        sb.delete()
        rootfs = tmp_path / "envs" / "bg-cleanup" / "rootfs"
        assert not rootfs.exists() or not os.path.ismount(str(rootfs))


# ------------------------------------------------------------------ #
#  Registry client                                                      #
# ------------------------------------------------------------------ #


def _skip_if_no_registry():
    """Skip test at runtime if Docker Hub API is unreachable or rate-limited."""
    from nitrobox._registry import get_diff_ids_from_registry
    try:
        if get_diff_ids_from_registry("alpine:3.19") is None:
            pytest.skip("Docker Hub unreachable or rate-limited")
    except (OSError, urllib.error.URLError, RuntimeError):
        pytest.skip("Docker Hub unreachable or rate-limited")


class TestRegistry:
    def test_parse_image_ref(self):
        """parse_image_ref correctly splits registry/repo/tag."""
        from nitrobox._registry import parse_image_ref

        assert parse_image_ref("ubuntu:22.04") == (
            "registry-1.docker.io", "library/ubuntu", "22.04")
        assert parse_image_ref("python:3.11-slim") == (
            "registry-1.docker.io", "library/python", "3.11-slim")
        assert parse_image_ref("nginx") == (
            "registry-1.docker.io", "library/nginx", "latest")
        assert parse_image_ref("ghcr.io/org/repo:v1") == (
            "ghcr.io", "org/repo", "v1")

    def test_get_diff_ids_from_registry(self):
        """Can get layer diff_ids directly from Docker Hub."""
        _skip_if_no_registry()
        from nitrobox._registry import get_diff_ids_from_registry

        ids = get_diff_ids_from_registry("ubuntu:22.04")
        if ids is None:
            pytest.skip("Docker Hub rate-limited for ubuntu:22.04")
        assert len(ids) >= 1
        assert all(d.startswith("sha256:") for d in ids)

    def test_get_config_from_registry(self):
        """Can get image config directly from Docker Hub."""
        _skip_if_no_registry()
        from nitrobox._registry import get_config_from_registry

        cfg = get_config_from_registry("python:3.11-slim")
        if cfg is None:
            pytest.skip("Docker Hub rate-limited for python:3.11-slim")
        assert cfg["cmd"] == ["python3"]

    def test_registry_fallback_layers(self, tmp_path):
        """Layer extraction works via registry when Docker/Podman unavailable."""
        _skip_if_no_registry()
        import nitrobox.rootfs as rf

        orig = rf._container_cli
        rf._container_cli = lambda: None  # Force registry path
        try:
            layers = rf.prepare_rootfs_layers_from_docker(
                "ubuntu:22.04", tmp_path / "cache",
            )
            assert len(layers) >= 1
            # Layer should have rootfs content
            assert (layers[0] / "bin").exists() or (layers[0] / "usr").exists()
        finally:
            rf._container_cli = orig


# ------------------------------------------------------------------ #
#  Snapshot API                                                         #
# ------------------------------------------------------------------ #


class TestSnapshot:
    def test_save_and_restore(self, sandbox):
        """snapshot() saves state, restore() returns to it."""
        sandbox.run("echo v1 > /workspace/data.txt")
        sid = sandbox.snapshot()
        sandbox.run("echo v2 > /workspace/data.txt")
        sandbox.restore(sid)
        out, _ = sandbox.run("cat /workspace/data.txt")
        assert "v1" in out

    def test_multiple_snapshots(self, sandbox):
        """Multiple snapshots with restore to any point."""
        sandbox.run("echo s0 > /workspace/log.txt")
        s0 = sandbox.snapshot()
        sandbox.run("echo s1 >> /workspace/log.txt")
        s1 = sandbox.snapshot()
        sandbox.run("echo s2 >> /workspace/log.txt")
        s2 = sandbox.snapshot()

        sandbox.restore(s0)
        out, _ = sandbox.run("cat /workspace/log.txt")
        assert out.strip() == "s0"

        sandbox.restore(s2)
        out, _ = sandbox.run("cat /workspace/log.txt")
        assert "s2" in out

    def test_list_snapshots(self, sandbox):
        """list_snapshots() returns sorted IDs."""
        s0 = sandbox.snapshot()
        s1 = sandbox.snapshot()
        assert sandbox.list_snapshots() == [s0, s1]

    def test_delete_snapshot(self, sandbox):
        """delete_snapshot() removes a specific snapshot."""
        s0 = sandbox.snapshot()
        s1 = sandbox.snapshot()
        sandbox.delete_snapshot(s0)
        assert sandbox.list_snapshots() == [s1]

    def test_restore_nonexistent_raises(self, sandbox):
        """restore() with invalid ID raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            sandbox.restore(999)

    def test_named_snapshot(self, sandbox):
        """snapshot() accepts string tags."""
        sandbox.run("echo tagged > /workspace/data.txt")
        sandbox.snapshot("my_tag")
        sandbox.run("echo changed > /workspace/data.txt")
        sandbox.restore("my_tag")
        out, _ = sandbox.run("cat /workspace/data.txt")
        assert "tagged" in out
        assert "my_tag" in [str(s) for s in sandbox.list_snapshots()]

    def test_restore_latest(self, sandbox):
        """restore() with no args restores to most recent snapshot."""
        sandbox.run("echo latest > /workspace/data.txt")
        sandbox.snapshot()
        sandbox.run("echo modified > /workspace/data.txt")
        sandbox.restore()
        out, _ = sandbox.run("cat /workspace/data.txt")
        assert "latest" in out

    def test_tree_branch(self, sandbox):
        """Simulate tree search: branch from a checkpoint."""
        sandbox.run("echo base > /workspace/state.txt")
        branch_point = sandbox.snapshot()

        # Branch A
        sandbox.run("echo branch_a >> /workspace/state.txt")
        out_a, _ = sandbox.run("cat /workspace/state.txt")

        # Restore and try Branch B
        sandbox.restore(branch_point)
        sandbox.run("echo branch_b >> /workspace/state.txt")
        out_b, _ = sandbox.run("cat /workspace/state.txt")

        assert "branch_a" in out_a and "branch_b" not in out_a
        assert "branch_b" in out_b and "branch_a" not in out_b


# ------------------------------------------------------------------ #
#  Async API                                                            #
# ------------------------------------------------------------------ #


class TestAsyncAPI:
    def test_arun(self, sandbox):
        """arun() returns same result as run()."""
        import asyncio
        output, ec = asyncio.run(sandbox.arun("echo async-hello"))
        assert ec == 0
        assert "async-hello" in output

    def test_areset(self, sandbox):
        """areset() resets filesystem."""
        import asyncio
        sandbox.run("echo data > /workspace/temp.txt")
        asyncio.run(sandbox.areset())
        _, ec = sandbox.run("cat /workspace/temp.txt 2>/dev/null")
        assert ec != 0

    def test_arun_concurrent(self, tmp_path, shared_cache_dir):
        """Multiple arun() calls can run concurrently on different sandboxes."""
        import asyncio
        _requires_root()
        _requires_docker()

        async def worker(i):
            config = SandboxConfig(
                image=TEST_IMAGE,
                working_dir="/workspace",
                env_base_dir=str(tmp_path / "envs"),
                rootfs_cache_dir=shared_cache_dir,
            )
            sb = Sandbox(config, name=f"async-{i}")
            try:
                out, ec = await sb.arun(f"echo worker-{i}")
                assert ec == 0
                assert f"worker-{i}" in out
            finally:
                await sb.adelete()

        async def main():
            await asyncio.gather(*(worker(i) for i in range(4)))

        asyncio.run(main())


class TestVmMode:
    """Tests for vm_mode=True sandbox init."""

    def test_sys_mounted(self, tmp_path, shared_cache_dir):
        """vm_mode sandbox has /sys mounted with contents."""
        config = SandboxConfig(
            image=TEST_IMAGE,
            vm_mode=True,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="vm-sys")
        try:
            out, ec = sb.run("ls /sys/kernel 2>&1")
            assert ec == 0
            assert out.strip(), "/sys/kernel should have contents"
        finally:
            sb.delete()

    def test_tmp_writable(self, tmp_path, shared_cache_dir):
        """vm_mode /tmp is writable (stays on overlayfs to preserve image files)."""
        config = SandboxConfig(
            image=TEST_IMAGE,
            vm_mode=True,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="vm-tmp")
        try:
            out, ec = sb.run("touch /tmp/test_file && echo ok")
            assert ec == 0
            assert "ok" in out
        finally:
            sb.delete()

    def test_run_is_tmpfs(self, tmp_path, shared_cache_dir):
        """vm_mode mounts tmpfs at /run."""
        config = SandboxConfig(
            image=TEST_IMAGE,
            vm_mode=True,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="vm-run")
        try:
            out, ec = sb.run("stat -f -c %T /run 2>/dev/null || stat -f /run 2>/dev/null")
            assert ec == 0
            assert "tmpfs" in out.lower(), f"/run should be tmpfs, got: {out}"
        finally:
            sb.delete()

    def test_mktemp_works(self, tmp_path, shared_cache_dir):
        """vm_mode sandbox can create temp files (no overlayfs inode overflow)."""
        config = SandboxConfig(
            image=TEST_IMAGE,
            vm_mode=True,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="vm-mktemp")
        try:
            out, ec = sb.run("mktemp")
            assert ec == 0
            assert "/tmp/" in out
        finally:
            sb.delete()

    def test_volumes_on_top_of_tmpfs(self, tmp_path, shared_cache_dir):
        """Directory volume bind-mounts work on top of tmpfs /run."""
        host_dir = tmp_path / "scripts"
        host_dir.mkdir()
        (host_dir / "test.sh").write_text("#!/bin/sh\necho hello\n")

        config = SandboxConfig(
            image=TEST_IMAGE,
            vm_mode=True,
            volumes=[f"{host_dir}:/run/scripts:ro"],
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="vm-vol-run")
        try:
            out, ec = sb.run("cat /run/scripts/test.sh")
            assert ec == 0
            assert "echo hello" in out
        finally:
            sb.delete()

    def test_proc_sys_not_readonly(self, tmp_path, shared_cache_dir):
        """vm_mode does not make /proc/sys read-only."""
        config = SandboxConfig(
            image=TEST_IMAGE,
            vm_mode=True,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="vm-procsys")
        try:
            # In vm_mode, /proc/sys should NOT have a read-only bind mount
            out, ec = sb.run("mount 2>/dev/null | grep 'proc/sys.*\\bro\\b' | wc -l")
            assert ec == 0
            count = int(out.strip())
            assert count == 0, f"/proc/sys should not be read-only in vm_mode, found {count} ro mounts"
        finally:
            sb.delete()

