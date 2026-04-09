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


def _requires_gobin():
    """Skip if images cannot be pulled (needs Go binary or Docker daemon)."""
    from nitrobox._gobin import gobin
    bin_path = gobin()
    if os.path.isfile(bin_path) and os.access(bin_path, os.X_OK):
        return  # Go binary available — can pull via containers/storage
    if subprocess.run(["docker", "info"], capture_output=True).returncode == 0:
        return  # Docker available — can pull via daemon
    pytest.skip("requires nitrobox-core Go binary or Docker daemon")


@pytest.fixture
def sandbox(tmp_path, shared_cache_dir):
    _requires_root()
    _requires_gobin()
    config = SandboxConfig(
        image=TEST_IMAGE,
        working_dir="/workspace",
        env_base_dir=str(tmp_path / "envs"),
        rootfs_cache_dir=shared_cache_dir,
    )
    box = Sandbox(config, name="test")
    yield box
    box.delete()


# ------------------------------------------------------------------ #
#  Basic lifecycle                                                     #
# ------------------------------------------------------------------ #


class TestLifecycle:
    def test_create_and_delete(self, tmp_path, shared_cache_dir):
        _requires_root()
        _requires_gobin()
        config = SandboxConfig(
            image=TEST_IMAGE,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="lifecycle")
        assert box.rootfs.exists()
        box.delete()
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
        _requires_gobin()
        config = SandboxConfig(
            image=TEST_IMAGE,
            environment={"MY_VAR": "test_value_123"},
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="env-test")
        output, ec = box.run("echo $MY_VAR")
        assert ec == 0
        assert "test_value_123" in output
        box.delete()

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

    def test_copy_to_directory(self, sandbox, tmp_path):
        """copy_to handles directories with subdirectories."""
        src_dir = tmp_path / "testdir"
        src_dir.mkdir()
        (src_dir / "file.txt").write_text("hello")
        sub = src_dir / "subdir"
        sub.mkdir()
        (sub / "nested.txt").write_text("nested")

        sandbox.copy_to(str(src_dir), "/workspace/testdir")

        out, ec = sandbox.run("cat /workspace/testdir/file.txt")
        assert out.strip() == "hello"
        out, ec = sandbox.run("cat /workspace/testdir/subdir/nested.txt")
        assert out.strip() == "nested"

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
        _requires_gobin()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="dead-dir-test")
        env_dir = tmp_path / "envs" / "dead-dir-test"

        for _ in range(5):
            box.run("seq 1 50 | xargs -I{} touch /workspace/f_{}")
            box.reset()

        box.delete()
        assert not env_dir.exists(), "env_dir not cleaned up by delete()"


# ------------------------------------------------------------------ #
#  Concurrency                                                         #
# ------------------------------------------------------------------ #


class TestConcurrency:
    def test_parallel_sandboxes(self, tmp_path, shared_cache_dir):
        _requires_root()
        _requires_gobin()
        n = 2  # CI runners have limited resources

        def run_worker(i):
            config = SandboxConfig(
                image=TEST_IMAGE,
                working_dir="/workspace",
                env_base_dir=str(tmp_path / "envs"),
                rootfs_cache_dir=shared_cache_dir,
            )
            box = Sandbox(config, name=f"parallel-{i}")
            output, ec = box.run(f"echo worker-{i}")
            box.delete()
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
    _requires_gobin()
    config = SandboxConfig(
        image=TEST_IMAGE,
        working_dir="/workspace",
        tty=True,
        env_base_dir=str(tmp_path / "envs"),
        rootfs_cache_dir=shared_cache_dir,
    )
    box = Sandbox(config, name="tty-test")
    yield box
    box.delete()


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
        _requires_gobin()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            net_isolate=True,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="net-test")
        output, ec = box.run("ip link show 2>/dev/null || cat /proc/net/dev")
        assert ec == 0
        # Should NOT have eth0 or any real interface
        assert "eth0" not in output
        box.delete()

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
        _requires_gobin()
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
        box = Sandbox(config, name="vol-ro")
        try:
            output, ec = box.run("cat /mnt/data/file.txt")
            assert ec == 0
            assert "host_content" in output

            # Write should fail
            _, ec = box.run("touch /mnt/data/new_file 2>&1")
            assert ec != 0
        finally:
            box.delete()

    def test_rw_volume(self, tmp_path, shared_cache_dir):
        _requires_root()
        _requires_gobin()
        host_dir = tmp_path / "host_rw"
        host_dir.mkdir()

        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            volumes=[f"{host_dir}:/mnt/data:rw"],
        )
        box = Sandbox(config, name="vol-rw")
        try:
            box.run("echo written_from_sandbox > /mnt/data/output.txt")
            assert (host_dir / "output.txt").read_text().strip() == "written_from_sandbox"
        finally:
            box.delete()


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
        _requires_gobin()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            cpu_max="50000 100000",
        )
        box = Sandbox(config, name="psi-test")
        try:
            psi = box.pressure()
            assert isinstance(psi, dict)
            if psi:  # cgroup v2 available
                assert "cpu" in psi
                assert "avg10" in psi["cpu"]
        finally:
            box.delete()

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
        _requires_gobin()
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
        _requires_gobin()
        if not _cgroup_v2_available():
            pytest.skip("cgroup v2 not available")

        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            memory_max="16777216",  # 16 MB
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="mem-limit")
        # Try to allocate 100 MB -- should fail or be killed
        _, ec = box.run(
            "python3 -c 'x = bytearray(100*1024*1024)' 2>&1",
            timeout=10,
        )
        assert ec != 0
        box.delete()

    def test_pids_limit_enforced(self, tmp_path, shared_cache_dir):
        """pids_max should be correctly written to the cgroup."""
        _requires_root()
        _requires_gobin()
        if not _cgroup_v2_available():
            pytest.skip("cgroup v2 not available")

        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            pids_max="42",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="pid-limit")
        # Verify cgroup pids.max is set correctly from the host side
        cgroup_path = box._cgroup_path
        assert cgroup_path is not None, "cgroup was not created"
        pids_max_value = (cgroup_path / "pids.max").read_text().strip()
        assert pids_max_value == "42", f"Expected pids.max=42, got {pids_max_value}"
        # Verify sandbox is still functional
        output, ec = box.run("echo pids-ok")
        assert ec == 0
        assert "pids-ok" in output
        box.delete()

    def test_cpu_max_accepted(self, tmp_path, shared_cache_dir):
        """cpu_max config should not cause errors during sandbox creation."""
        _requires_root()
        _requires_gobin()
        if not _cgroup_v2_available():
            pytest.skip("cgroup v2 not available")

        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            cpu_max="50000 100000",  # 50% of one CPU
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="cpu-limit")
        output, ec = box.run("echo cpu-ok")
        assert ec == 0
        assert "cpu-ok" in output
        box.delete()


class TestRootlessCgroupSetup:
    """Unit tests for rootless cgroup delegation logic (no root needed)."""

    def _make_sandbox_stub(self, tmp_path, limits=None):
        """Create a minimal Sandbox stub for testing cgroup methods."""
        s = Sandbox.__new__(Sandbox)
        s._userns = True
        s._cgroup_path = None
        s._systemd_scope_name = None
        s._systemd_scope_pid = None
        s._env_dir = tmp_path / "test-env"
        s._env_dir.mkdir()
        s._cgroup_limits = {
            "cpu_max": None, "memory_max": None, "memory_high": None,
            "pids_max": None, "io_max": None, "cpuset_cpus": None,
            "cpuset_mems": None, "cpu_shares": None, "memory_swap": None,
        }
        if limits:
            s._cgroup_limits.update(limits)
        return s

    def test_no_limits_skips(self, tmp_path):
        """No limits → _setup_cgroup_rootless is a no-op."""
        s = self._make_sandbox_stub(tmp_path)
        s._setup_cgroup_rootless()
        assert s._cgroup_path is None

    def test_try_own_cgroup_parses_proc(self, tmp_path):
        """_try_own_cgroup reads /proc/self/cgroup correctly."""
        s = self._make_sandbox_stub(tmp_path, {"memory_max": "256M"})
        # Even if it fails permission-wise, it should not raise
        result = s._try_own_cgroup()
        # On this machine without delegation it returns None
        # On a machine with delegation it would return a Path
        assert result is None or isinstance(result, Path)

    def test_preallocated_cgroup_used(self, tmp_path):
        """Pre-allocated cgroup at /sys/fs/cgroup/nitrobox is used when available."""
        s = self._make_sandbox_stub(tmp_path, {"memory_max": "256M"})
        preallocated = Path("/sys/fs/cgroup/nitrobox")
        if preallocated.exists() and os.access(preallocated, os.W_OK):
            s._setup_cgroup_rootless()
            assert s._cgroup_path is not None
            # Cleanup the child cgroup we created
            from nitrobox._core import py_cleanup_cgroup
            py_cleanup_cgroup(str(s._cgroup_path))
        else:
            s._setup_cgroup_rootless()
            # Without delegation, cgroup_path may be None
            assert s._cgroup_path is None or isinstance(s._cgroup_path, Path)

    def test_cleanup_cgroup_noop_when_none(self, tmp_path):
        """_cleanup_cgroup with no cgroup_path is a no-op."""
        s = self._make_sandbox_stub(tmp_path)
        s._cleanup_cgroup()  # Should not raise


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
        _requires_gobin()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="dead-sandbox")
        box.delete()
        # rootfs is gone, so run() should raise (shell can't restart)
        from nitrobox._errors import SandboxError
        with pytest.raises((RuntimeError, OSError, SandboxError)):
            box.run("echo hello")

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

    def test_deep_layer_overlay(self, tmp_path):
        """Mount overlay with 50 layers — exercises PAGE_SIZE fallback.

        Matching Podman's TestOverlay128LayerRead: creates many layers,
        mounts overlay, and verifies files from bottom and top layers
        are readable.  Requires root (overlay mount is a privileged op).
        """
        _requires_root()
        from nitrobox._core import py_mount_overlay, py_umount_lazy

        n_layers = 50
        layers_dir = tmp_path / "layers"
        layers_dir.mkdir()

        # Create N layer dirs with 64-char names (like full SHA256)
        layer_paths = []
        for i in range(n_layers):
            layer = layers_dir / f"{i:064x}"
            layer.mkdir()
            if i == 0:
                (layer / "bottom.txt").write_text("from layer 0")
            if i == n_layers - 1:
                (layer / "top.txt").write_text("from top layer")
            layer_paths.append(str(layer))

        upper = tmp_path / "upper"
        work = tmp_path / "work"
        merged = tmp_path / "merged"
        for d in (upper, work, merged):
            d.mkdir()

        # lowerdir: first in list = topmost layer
        lowerdir_spec = ":".join(reversed(layer_paths))
        py_mount_overlay(lowerdir_spec, str(upper), str(work), str(merged))

        try:
            assert (merged / "bottom.txt").read_text() == "from layer 0"
            assert (merged / "top.txt").read_text() == "from top layer"
        finally:
            py_umount_lazy(str(merged))


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
        _requires_gobin()
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
        box = Sandbox(config, name="port-test")
        try:
            box.run_background("python3 -m http.server 8000 --directory /tmp")

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
            box.delete()

    def test_internal_loopback(self, tmp_path, shared_cache_dir):
        """Loopback is automatically brought up inside net-isolated sandbox."""
        _requires_root()
        _requires_tun()
        _requires_gobin()

        config = SandboxConfig(
            image="python:3.11-slim",
            working_dir="/tmp",
            net_isolate=True,
            port_map=["19877:8000"],
            seccomp=False,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="lo-test")
        try:
            box.run_background("python3 -m http.server 8000 --directory /tmp")

            box.write_file("/tmp/lo_check.py",
                "import urllib.request, time\n"
                "for _ in range(20):\n"
                "    try:\n"
                "        r = urllib.request.urlopen('http://127.0.0.1:8000/')\n"
                "        print(r.status); break\n"
                "    except Exception: time.sleep(0.3)\n"
                "else: print('FAIL')\n"
            )
            output, ec = box.run("python3 /tmp/lo_check.py")
            assert ec == 0
            assert "200" in output
        finally:
            box.delete()

    def test_delete_cleans_netns_rootful(self, tmp_path, shared_cache_dir):
        """delete() with port_map leaves no stale netns bind mounts (rootful)."""
        _requires_root()
        _requires_tun()
        _requires_gobin()

        config = SandboxConfig(
            image=TEST_IMAGE,
            net_isolate=True,
            port_map=["19878:8000"],
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="netns-cleanup")
        env_dir = box._env_dir
        box.delete()

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
        _requires_gobin()

        config = SandboxConfig(
            image=TEST_IMAGE,
            net_isolate=True,
            port_map=["19878:8000"],
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="netns-cleanup-u")
        env_dir = box._env_dir
        box.delete()

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
        _requires_gobin()

        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="clean-test")
        # Create some files inside sandbox
        box.run("echo test > /workspace/file.txt")
        box.run("mkdir -p /workspace/subdir && echo nested > /workspace/subdir/a.txt")
        env_dir = box._env_dir
        box.delete()

        assert not env_dir.exists(), \
            f"env_dir still exists after delete: {list(env_dir.rglob('*')) if env_dir.exists() else []}"

    def test_delete_kills_shell_process(self, tmp_path, shared_cache_dir):
        """delete() kills the persistent shell process — no zombies."""
        _requires_root()
        _requires_gobin()

        config = SandboxConfig(
            image=TEST_IMAGE,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="proc-clean")
        shell_pid = box._persistent_shell.pid
        assert shell_pid is not None

        box.delete()

        # Process should be dead
        import signal
        with pytest.raises(ProcessLookupError):
            os.kill(shell_pid, signal.SIG_DFL)

    def test_reset_no_mount_leak(self, tmp_path, shared_cache_dir):
        """Multiple resets don't accumulate bind mounts."""
        _requires_root()
        _requires_gobin()

        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="mount-leak")
        try:
            import subprocess
            before = subprocess.run(["mount"], capture_output=True, text=True).stdout.count("mount-leak")
            for _ in range(5):
                box.reset()
            after = subprocess.run(["mount"], capture_output=True, text=True).stdout.count("mount-leak")
            # Mount count should not grow with resets
            assert after <= before + 2, \
                f"Mount leak: {before} mounts before, {after} after 5 resets"
        finally:
            box.delete()

    def test_delete_no_stale_cgroup(self, tmp_path, shared_cache_dir):
        """delete() removes the cgroup directory."""
        _requires_root()
        _requires_gobin()

        config = SandboxConfig(
            image=TEST_IMAGE,
            memory_max="256m",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="cg-clean")
        cgroup_path = box._cgroup_path
        box.delete()

        if cgroup_path:
            assert not cgroup_path.exists(), f"cgroup not cleaned: {cgroup_path}"


# ------------------------------------------------------------------ #
#  Crash + cleanup_stale                                                #
# ------------------------------------------------------------------ #


class TestCleanupAfterCrash:
    """Verify cleanup_stale recovers all resources after a simulated crash.

    Creates a real sandbox, kills the shell with SIGKILL to simulate a
    crash, then verifies that cleanup_stale removes overlay mounts,
    cgroup directories, and sandbox env directories (including
    mapped-UID files from userns sandboxes).
    """

    def test_cleanup_stale_after_sigkill(self, tmp_path, shared_cache_dir):
        """SIGKILL the shell, then cleanup_stale should remove everything."""
        _requires_gobin()

        env_dir = str(tmp_path / "envs")
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=env_dir,
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="crash-test")
        sandbox_dir = tmp_path / "envs" / "crash-test"

        # Write some files (creates mapped-UID files in overlay upper)
        box.run("touch /workspace/file1 /workspace/file2")

        # Record state before crash
        pid = box._persistent_shell.pid
        cgroup_path = box._cgroup_path

        # Simulate crash: kill shell with SIGKILL (no cleanup runs)
        os.kill(pid, 9)
        os.waitpid(pid, 0)

        # Sandbox dir should still exist (orphaned)
        assert sandbox_dir.exists(), "sandbox dir should still exist after crash"

        # Now run cleanup_stale
        cleaned = Sandbox.cleanup_stale(env_dir)
        assert cleaned >= 1, f"cleanup_stale should have cleaned at least 1, got {cleaned}"

        # Verify: no sandbox dir (or only stale userns mounts that need root)
        if sandbox_dir.exists():
            rootfs = sandbox_dir / "rootfs"
            if rootfs.exists() and rootfs.is_mount():
                pytest.skip(
                    "stale userns mount — needs root or reboot to unmount "
                    "(known Linux limitation for rootless)"
                )
            else:
                pytest.fail(
                    f"sandbox dir not cleaned: "
                    f"{list(sandbox_dir.iterdir()) if sandbox_dir.exists() else 'N/A'}"
                )

        # Verify: no mounts under env_dir
        mount_output = subprocess.run(["mount"], capture_output=True, text=True).stdout
        assert "crash-test" not in mount_output, \
            f"stale mount found: {[l for l in mount_output.splitlines() if 'crash-test' in l]}"

        # Verify: no cgroup
        if cgroup_path:
            assert not cgroup_path.exists(), f"cgroup not cleaned: {cgroup_path}"

    def test_cleanup_stale_mapped_uid_files(self, tmp_path, shared_cache_dir):
        """Crash with mapped-UID files in overlay upper — cleanup must use rmtree_mapped."""
        _requires_gobin()

        env_dir = str(tmp_path / "envs")
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=env_dir,
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="crash-mapped-uid")
        sandbox_dir = tmp_path / "envs" / "crash-mapped-uid"

        # Create files owned by different UIDs inside the sandbox
        box.run("adduser --disabled-password --gecos '' testuser 2>/dev/null || true")
        box.run("su testuser -c 'touch /workspace/owned_by_testuser'")

        pid = box._persistent_shell.pid
        os.kill(pid, 9)
        os.waitpid(pid, 0)

        cleaned = Sandbox.cleanup_stale(env_dir)
        assert cleaned >= 1

        if sandbox_dir.exists():
            rootfs = sandbox_dir / "rootfs"
            if rootfs.exists() and rootfs.is_mount():
                pytest.skip("stale userns mount — needs root")
            else:
                pytest.fail("sandbox with mapped-UID files not cleaned")

    def test_cleanup_stale_multiple_crashed(self, tmp_path, shared_cache_dir):
        """Multiple crashed sandboxes cleaned in one call."""
        _requires_gobin()

        env_dir = str(tmp_path / "envs")
        boxes = []
        for i in range(3):
            config = SandboxConfig(
                image=TEST_IMAGE,
                working_dir="/workspace",
                env_base_dir=env_dir,
                rootfs_cache_dir=shared_cache_dir,
            )
            box = Sandbox(config, name=f"multi-crash-{i}")
            box.run(f"echo sandbox-{i}")
            boxes.append(box)

        # Kill all shells
        for box in boxes:
            pid = box._persistent_shell.pid
            os.kill(pid, 9)
            os.waitpid(pid, 0)

        cleaned = Sandbox.cleanup_stale(env_dir)
        assert cleaned == 3, f"expected 3 cleaned, got {cleaned}"

    def test_cleanup_stale_orphan_no_pid(self, tmp_path, shared_cache_dir):
        """Sandbox dir with no .pid file (partial init crash) is cleaned."""
        _requires_gobin()

        env_dir = str(tmp_path / "envs")
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=env_dir,
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="orphan-test")
        sandbox_dir = tmp_path / "envs" / "orphan-test"

        # Write files, then simulate partial cleanup: remove .pid but leave dirs
        box.run("touch /workspace/data")
        pid = box._persistent_shell.pid
        os.kill(pid, 9)
        os.waitpid(pid, 0)
        pid_file = sandbox_dir / ".pid"
        if pid_file.exists():
            pid_file.unlink()

        # upper/ and work/ exist but no .pid — this is the orphan case
        assert (sandbox_dir / "upper").exists() or (sandbox_dir / "work").exists()

        cleaned = Sandbox.cleanup_stale(env_dir)
        assert cleaned >= 1, "orphan dir should be cleaned"


# ------------------------------------------------------------------ #
#  Layer cache                                                          #
# ------------------------------------------------------------------ #


class TestLayerCache:
    def test_shared_layers(self, tmp_path, shared_cache_dir):
        """Two images sharing base layers reuse cached layers."""
        _requires_root()
        _requires_gobin()

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
            box = Sandbox(config, name=f"layer-test-{i}")
            configs.append(config)
            sandboxes.append(box)

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
            for box in sandboxes:
                box.delete()

    def test_multi_layer_image(self, tmp_path, shared_cache_dir):
        """An image with many layers mounts and works correctly."""
        _requires_root()
        _requires_gobin()

        config = SandboxConfig(
            image="python:3.11-slim",  # 4 layers
            working_dir="/tmp",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="multi-layer")
        try:
            assert box._layer_dirs is not None
            assert len(box._layer_dirs) >= 4

            output, ec = box.run("python3 -c 'print(1+1)'")
            assert ec == 0
            assert "2" in output

            # Reset should work with multi-layer
            box.run("touch /tmp/marker")
            box.reset()
            output, ec = box.run("test -f /tmp/marker && echo yes || echo no")
            assert "no" in output
        finally:
            box.delete()


# ------------------------------------------------------------------ #
#  Seccomp clone3 → ENOSYS (threading must work)                       #
# ------------------------------------------------------------------ #


class TestClone3Fallback:
    def test_threading_works_with_seccomp(self, tmp_path, shared_cache_dir):
        """clone3 returns ENOSYS so glibc falls back to clone(2), allowing threads."""
        _requires_root()
        _requires_gobin()
        config = SandboxConfig(
            image="python:3.11-slim",
            working_dir="/tmp",
            seccomp=True,  # seccomp ON — clone3 should get ENOSYS
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="clone3-test")
        try:
            # Python threading uses clone/clone3 under the hood
            output, ec = box.run(
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
            box.delete()


# ------------------------------------------------------------------ #
#  Hostname configuration                                              #
# ------------------------------------------------------------------ #


class TestHostname:
    def test_custom_hostname(self, tmp_path, shared_cache_dir):
        """hostname= sets the UTS hostname inside the sandbox."""
        _requires_root()
        _requires_gobin()
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
        box = Sandbox(config, name="hostname-test")
        try:
            output, ec = box.run("hostname")
            assert ec == 0
            assert "my-sandbox" in output.strip()
        finally:
            box.delete()


class TestDnsReset:
    """Verify DNS config persists after reset."""

    def test_dns_survives_reset(self, tmp_path, shared_cache_dir):
        _requires_root()
        _requires_gobin()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            dns=["8.8.8.8", "1.1.1.1"],
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="dns-reset-test")
        try:
            box.reset()
            output, ec = box.run("cat /etc/resolv.conf")
            assert ec == 0
            assert "8.8.8.8" in output, "dns config lost after reset"
            assert "1.1.1.1" in output
        finally:
            box.delete()


# ------------------------------------------------------------------ #
#  Read-only root filesystem                                           #
# ------------------------------------------------------------------ #


class TestReadOnly:
    def test_read_only_rootfs(self, tmp_path, shared_cache_dir):
        """read_only=True makes root filesystem read-only."""
        _requires_root()
        _requires_gobin()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/",
            read_only=True,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="ro-test")
        try:
            # Writes to rootfs should fail
            _, ec = box.run("touch /test_file 2>/dev/null")
            assert ec != 0
            # Reads should work
            output, ec = box.run("cat /etc/hostname 2>/dev/null || echo ok")
            assert ec == 0
        finally:
            box.delete()

    def test_read_only_survives_reset(self, tmp_path, shared_cache_dir):
        """read_only is preserved after reset()."""
        _requires_root()
        _requires_gobin()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/",
            read_only=True,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="ro-reset")
        try:
            _, ec = box.run("touch /test_file 2>/dev/null")
            assert ec != 0
            box.reset()
            _, ec = box.run("touch /test_file 2>/dev/null")
            assert ec != 0
        finally:
            box.delete()

    def test_read_only_without_seccomp(self, tmp_path, shared_cache_dir):
        """read_only works even when seccomp is disabled."""
        _requires_root()
        _requires_gobin()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/",
            read_only=True,
            seccomp=False,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="ro-nosec")
        try:
            _, ec = box.run("touch /test_file 2>/dev/null")
            assert ec != 0
        finally:
            box.delete()


# ------------------------------------------------------------------ #
#  get_image_config                                                    #
# ------------------------------------------------------------------ #


class TestParseCpuMax:
    """Unit tests for _parse_cpu_max sugar."""

    @pytest.mark.parametrize("input_val,expected", [
        ("0.5", "50000 100000"),
        ("2", "200000 100000"),
        ("50%", "50000 100000"),
        ("50000 100000", "50000 100000"),
        ("0.01", "1000 100000"),
    ])
    def test_parse(self, input_val, expected):
        from nitrobox.config import _parse_cpu_max
        result = _parse_cpu_max(input_val)
        # For small fractions, verify quota >= 1 and period is correct
        quota, period = result.split()
        exp_quota, exp_period = expected.split()
        assert int(quota) >= 1
        assert int(quota) == int(exp_quota)
        assert period == exp_period

    def test_config_applies(self):
        """SandboxConfig.__post_init__ converts friendly cpu_max."""
        cfg = SandboxConfig(image="x", cpu_max="0.5")
        assert cfg.cpu_max == "50000 100000"


class TestParseIoMax:
    """Unit tests for _parse_io_max sugar."""

    @pytest.mark.parametrize("input_val,expected_fragments", [
        ("259:0 10mb", ["259:0 wbps=10485760"]),
        ("259:0 wbps=10mb", ["259:0 wbps=10485760"]),
        ("259:0 rbps=5mb wbps=10mb", ["rbps=5242880", "wbps=10485760"]),
        ("259:0 wbps=10485760", ["259:0 wbps=10485760"]),
    ])
    def test_parse(self, input_val, expected_fragments):
        from nitrobox.config import _parse_io_max
        result = _parse_io_max(input_val)
        for fragment in expected_fragments:
            assert fragment in result

    def test_config_applies(self):
        """SandboxConfig.__post_init__ converts friendly io_max."""
        cfg = SandboxConfig(image="x", io_max="259:0 10mb")
        assert cfg.io_max == "259:0 wbps=10485760"


class TestCpuShares:
    """Unit tests for _convert_cpu_shares."""

    @pytest.mark.parametrize("input_val,check", [
        (1024, lambda r: 1 <= r <= 10000),
        (2, lambda r: r >= 1),
        (262144, lambda r: r == 10000),
    ])
    def test_convert(self, input_val, check):
        from nitrobox.config import _convert_cpu_shares
        assert check(_convert_cpu_shares(input_val))

    def test_from_docker(self):
        cfg = SandboxConfig.from_docker("img", cpu_shares=512)
        assert cfg.cpu_shares == 512

    def test_from_docker_run(self):
        cfg = SandboxConfig.from_docker_run("docker run --cpu-shares=2048 ubuntu")
        assert cfg.cpu_shares == 2048


class TestShmSizeParsing:
    """Unit tests for shm_size parsing."""

    @pytest.mark.parametrize("input_val,expected", [
        (("config", "256m"), str(256 * 1024**2)),
        (("from_docker", "2g"), str(2 * 1024**3)),
        (("from_docker_run", "512m"), str(512 * 1024**2)),
    ])
    def test_parse(self, input_val, expected):
        source, size = input_val
        if source == "config":
            cfg = SandboxConfig(image="x", shm_size=size)
        elif source == "from_docker":
            cfg = SandboxConfig.from_docker("img", shm_size=size)
        elif source == "from_docker_run":
            cfg = SandboxConfig.from_docker_run(f"docker run --shm-size={size} ubuntu")
        assert cfg.shm_size == expected


class TestMemorySwap:
    """Unit tests for memory_swap Docker→cgroup v2 conversion."""

    @pytest.mark.parametrize("input_val,expected", [
        (("config", {"memory_swap": "-1"}), "max"),
        (("config", {"memory_swap": "0"}), None),
        (("config", {"memory_max": "512m", "memory_swap": "1g"}),
         str(1024**3 - 512 * 1024**2)),
        (("from_docker", {"mem_limit": "512m", "memswap_limit": "1g"}),
         str(1024**3 - 512 * 1024**2)),
        (("from_docker_run", "docker run -m 512m --memory-swap=1g ubuntu"),
         str(1024**3 - 512 * 1024**2)),
    ])
    def test_swap(self, input_val, expected):
        source, args = input_val
        if source == "config":
            cfg = SandboxConfig(image="x", **args)
        elif source == "from_docker":
            cfg = SandboxConfig.from_docker("img", **args)
        elif source == "from_docker_run":
            cfg = SandboxConfig.from_docker_run(args)
        assert cfg.memory_swap == expected


class TestTmpfs:
    """Unit tests for tmpfs parsing."""

    @pytest.mark.parametrize("input_val,expected_items", [
        (("from_docker", {"tmpfs": {"/run": "size=100m"}}),
         ["/run:size=100m"]),
        (("from_docker_run",
          "docker run --tmpfs /run:size=100m --tmpfs /tmp ubuntu"),
         ["/run:size=100m", "/tmp"]),
        (("config", {"tmpfs": ["/run:size=50m"]}),
         ["/run:size=50m"]),
    ])
    def test_parse(self, input_val, expected_items):
        source, args = input_val
        if source == "from_docker":
            cfg = SandboxConfig.from_docker("img", **args)
        elif source == "from_docker_run":
            cfg = SandboxConfig.from_docker_run(args)
        elif source == "config":
            cfg = SandboxConfig(image="x", **args)
        for item in expected_items:
            assert item in cfg.tmpfs


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
        _requires_gobin()
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
        _requires_gobin()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="bg-cleanup")
        box.run_background("sleep 3600")
        box.run_background("sleep 3600")
        # delete should not leave mount points behind
        box.delete()
        rootfs = tmp_path / "envs" / "bg-cleanup" / "rootfs"
        assert not rootfs.exists() or not os.path.ismount(str(rootfs))


# ------------------------------------------------------------------ #
#  Registry client                                                      #
# ------------------------------------------------------------------ #


def _skip_if_no_registry():
    """Skip test at runtime if Docker Hub API is unreachable or rate-limited."""
    from nitrobox._registry import get_image_metadata_from_registry
    try:
        get_image_metadata_from_registry("alpine:3.19")
    except Exception:
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
        from nitrobox._registry import get_image_metadata_from_registry

        metadata = get_image_metadata_from_registry("ubuntu:22.04")
        diff_ids = metadata["diff_ids"]
        assert len(diff_ids) >= 1
        assert all(d.startswith("sha256:") for d in diff_ids)

    def test_get_config_from_registry(self):
        """Can get image config directly from Docker Hub."""
        _skip_if_no_registry()
        from nitrobox._registry import get_image_metadata_from_registry

        cfg = get_image_metadata_from_registry("python:3.11-slim")
        assert cfg["cmd"] == ["python3"]

    def test_registry_pull_to_storage(self, tmp_path):
        """Image pull via containers/storage works."""
        _skip_if_no_registry()
        from nitrobox.image.layers import (
            _containers_storage_pull,
            _get_store_layers,
        )

        # Pull if not already in store
        if _get_store_layers("alpine:latest") is None:
            assert _containers_storage_pull("alpine:latest"), "pull failed"

        layers = _get_store_layers("alpine:latest")
        assert layers is not None
        assert len(layers) >= 1
        assert (layers[0] / "bin").exists()


# ------------------------------------------------------------------ #
#  Image pull pipeline                                                   #
# ------------------------------------------------------------------ #


class TestImagePullPipeline:
    """Test the image pull pipeline:

    1. containers/storage local cache hit (zero-copy, instant)
    2. ``docker://`` registry pull (standard path)
    3. ``docker-daemon:`` fallback (for local-only Docker images)

    Plus: image delete, pull failure handling.
    """

    @staticmethod
    def _skip_if_no_gobin():
        from nitrobox._gobin import gobin
        import shutil
        if not shutil.which(gobin()) and not os.path.isfile(gobin()):
            pytest.skip("nitrobox-core Go binary not found")

    @staticmethod
    def _skip_if_no_docker():
        """Skip if Docker daemon is not accessible."""
        if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
            pytest.skip("Docker daemon not available")

    # -- Layer 1: containers/storage local cache ---------------------- #

    def test_store_local_hit(self):
        """Image already in containers/storage is returned without pull."""
        self._skip_if_no_gobin()
        _skip_if_no_registry()
        from nitrobox.image.layers import (
            _containers_storage_pull,
            _get_store_layers,
            prepare_rootfs_layers_from_docker,
        )
        from pathlib import Path

        # Ensure alpine is in store (pull once)
        if _get_store_layers("alpine:latest") is None:
            assert _containers_storage_pull("alpine:latest"), "initial pull failed"

        # Now call with pull=False — should succeed from local store
        layers = prepare_rootfs_layers_from_docker("alpine:latest", Path("/tmp"), pull=False)
        assert layers is not None
        assert len(layers) >= 1
        assert layers[0].exists()

    def test_store_local_miss_pull_false_raises(self):
        """pull=False with image not in store raises RuntimeError."""
        self._skip_if_no_gobin()
        from nitrobox.image.layers import prepare_rootfs_layers_from_docker
        from pathlib import Path

        with pytest.raises(RuntimeError, match="not found"):
            prepare_rootfs_layers_from_docker(
                "nonexistent/image:v999", Path("/tmp"), pull=False,
            )

    # -- Layer 2: Registry pull ---------------------------------------- #

    def test_pull_from_registry(self):
        """Image not in store is pulled from registry."""
        self._skip_if_no_gobin()
        _skip_if_no_registry()
        from nitrobox.image.layers import (
            _containers_storage_pull,
            _get_store_layers,
        )

        image = "alpine:3.19"

        # Remove from containers/storage
        if _get_store_layers(image) is not None:
            self._delete_image(image)

        transport = _containers_storage_pull(image)
        assert transport, "registry pull failed"
        assert transport == "docker", \
            f"expected docker (registry) transport, got {transport!r}"

        layers = _get_store_layers(image)
        assert layers is not None
        assert len(layers) >= 1
        has_content = any(
            (d / "bin").exists() or (d / "usr").exists()
            for d in layers
        )
        assert has_content, "pulled image has no rootfs content"

    # -- Layer 3: Docker daemon fallback ------------------------------- #

    def test_pull_docker_daemon_fallback(self):
        """Image only in Docker (not on registry) uses docker-daemon fallback."""
        self._skip_if_no_gobin()
        self._skip_if_no_docker()
        from nitrobox.image.layers import (
            _containers_storage_pull,
            _get_store_layers,
        )

        # Build a local-only image in Docker (not on any registry)
        tag = "nbx-test-local-only:latest"
        subprocess.run(
            ["docker", "build", "-t", tag, "-"],
            input=b"FROM alpine:latest\nRUN echo local > /marker.txt\n",
            capture_output=True, timeout=120,
        )

        # Remove from containers/storage
        if _get_store_layers(tag) is not None:
            self._delete_image(tag)

        # Pull — registry fails (image doesn't exist), falls back to docker-daemon
        transport = _containers_storage_pull(tag)
        assert transport, "pull failed"
        assert transport == "docker-daemon", \
            f"expected docker-daemon fallback, got {transport!r}"

        layers = _get_store_layers(tag)
        assert layers is not None

        # Cleanup
        subprocess.run(["docker", "rmi", "-f", tag], capture_output=True)

    def test_pull_nonexistent_image_fails(self):
        """Pulling a nonexistent image returns False."""
        self._skip_if_no_gobin()
        from nitrobox.image.layers import _containers_storage_pull

        result = _containers_storage_pull("nonexistent-registry.invalid/no-image:v999")
        assert result is False

    # -- Image delete ------------------------------------------------- #

    @staticmethod
    def _delete_image(image: str) -> subprocess.CompletedProcess:
        """Call image-delete with same graph_root/run_root as pull."""
        import json
        from nitrobox._gobin import gobin
        from nitrobox.image.layers import _containers_storage_root
        graph_root = _containers_storage_root()
        if graph_root is None:
            from pathlib import Path
            graph_root = Path.home() / ".local/share/containers/storage"
        req = json.dumps({
            "image": image,
            "graph_root": str(graph_root),
            "run_root": f"/tmp/nitrobox-containers-run-{os.getuid()}",
        })
        env = dict(os.environ)
        env["_NITROBOX_DELETE_CONFIG"] = req
        return subprocess.run(
            [gobin(), "image-delete"],
            capture_output=True, env=env, timeout=30,
        )

    def test_image_delete(self):
        """image-delete removes an image from containers/storage."""
        self._skip_if_no_gobin()
        _skip_if_no_registry()
        from nitrobox.image.layers import (
            _containers_storage_pull,
            _get_store_layers,
        )

        image = "alpine:3.19"

        # Ensure it's in store
        if _get_store_layers(image) is None:
            assert _containers_storage_pull(image), "pull failed"
        assert _get_store_layers(image) is not None

        # Delete it
        r = self._delete_image(image)
        assert r.returncode == 0, f"image-delete failed: {r.stderr.decode()[:200]}"

        # Verify gone
        assert _get_store_layers(image) is None, "image still in store after delete"

    def test_image_delete_nonexistent_is_noop(self):
        """Deleting a nonexistent image succeeds (no-op, like docker rmi)."""
        self._skip_if_no_gobin()

        r = self._delete_image("nonexistent/image:v999")
        assert r.returncode == 0

    # -- End-to-end: prepare_rootfs_layers_from_docker ---------------- #

    def test_prepare_rootfs_full_pipeline(self):
        """prepare_rootfs_layers_from_docker pulls and caches end-to-end."""
        self._skip_if_no_gobin()
        _skip_if_no_registry()
        from nitrobox.image.layers import (
            _get_store_layers,
            prepare_rootfs_layers_from_docker,
        )
        from nitrobox._gobin import gobin
        from pathlib import Path

        image = "alpine:3.19"

        # Clean slate: remove from store
        if _get_store_layers(image) is not None:
            self._delete_image(image)

        # First call: should pull (from Docker daemon or registry)
        layers1 = prepare_rootfs_layers_from_docker(image, Path("/tmp"), pull=True)
        assert len(layers1) >= 1
        assert all(d.exists() for d in layers1)

        # Second call: should hit containers/storage cache (no pull)
        layers2 = prepare_rootfs_layers_from_docker(image, Path("/tmp"), pull=False)
        assert layers1 == layers2


# ------------------------------------------------------------------ #
#  Layer locking                                                        #
# ------------------------------------------------------------------ #


class TestLayerLocking:
    """Test acquire_layer_locks / release_layer_locks / remove_layer_locked."""

    def test_acquire_release_round_trip(self, tmp_path):
        """Acquire shared locks, then release — no errors."""
        from nitrobox.image.layers import acquire_layer_locks, release_layer_locks

        dirs = []
        for i in range(3):
            d = tmp_path / f"layer_{i}" / "diff"
            d.mkdir(parents=True)
            dirs.append(d)

        fds = acquire_layer_locks(dirs)
        assert len(fds) == 3
        assert all(isinstance(fd, int) and fd >= 0 for fd in fds)
        release_layer_locks(fds)

    def test_concurrent_shared_locks(self, tmp_path):
        """Multiple shared locks on the same layer don't block."""
        from nitrobox.image.layers import acquire_layer_locks, release_layer_locks

        d = tmp_path / "shared_layer" / "diff"
        d.mkdir(parents=True)

        fds1 = acquire_layer_locks([d])
        fds2 = acquire_layer_locks([d])  # should not block
        assert len(fds1) == 1 and len(fds2) == 1

        release_layer_locks(fds1)
        release_layer_locks(fds2)

    def test_remove_layer_locked_skips_when_held(self, tmp_path):
        """remove_layer_locked skips deletion when shared lock is held."""
        from nitrobox.image.layers import (
            acquire_layer_locks,
            release_layer_locks,
            remove_layer_locked,
        )

        d = tmp_path / "locked_layer" / "diff"
        d.mkdir(parents=True)
        (d / "file.txt").write_text("keep me")

        # Hold a shared lock
        fds = acquire_layer_locks([d])
        # Try to delete — should skip (LOCK_NB fails)
        remove_layer_locked(d)
        assert d.exists(), "layer dir should survive when lock is held"
        assert (d / "file.txt").exists()

        release_layer_locks(fds)

    def test_remove_layer_locked_deletes_when_free(self, tmp_path):
        """remove_layer_locked deletes when no lock is held."""
        from nitrobox.image.layers import remove_layer_locked

        d = tmp_path / "free_layer" / "diff"
        d.mkdir(parents=True)
        (d / "file.txt").write_text("delete me")

        remove_layer_locked(d)
        assert not d.exists(), "layer dir should be deleted when no lock held"


# ------------------------------------------------------------------ #
#  rmtree_mapped                                                        #
# ------------------------------------------------------------------ #


class TestRmtreeMapped:
    """Test rmtree_mapped for normal and mapped-UID directories."""

    def test_normal_directory(self, tmp_path):
        """rmtree_mapped removes a normal user-owned directory."""
        from nitrobox.image.layers import rmtree_mapped

        d = tmp_path / "normal"
        d.mkdir()
        (d / "file.txt").write_text("hello")
        (d / "sub").mkdir()
        (d / "sub" / "nested.txt").write_text("nested")

        rmtree_mapped(d)
        assert not d.exists()

    def test_nonexistent_is_noop(self, tmp_path):
        """rmtree_mapped on nonexistent path does nothing."""
        from nitrobox.image.layers import rmtree_mapped

        rmtree_mapped(tmp_path / "does_not_exist")  # should not raise

    def test_mapped_uid_directory(self, tmp_path, shared_cache_dir):
        """rmtree_mapped handles directories with mapped-UID files."""
        _requires_gobin()
        from nitrobox import Sandbox, SandboxConfig
        from nitrobox.image.layers import rmtree_mapped

        # Create a sandbox that writes files as mapped UIDs
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="rmtree-test")
        box.run("touch /workspace/mapped_file")

        # Get the upper dir (contains mapped-UID files)
        upper = box._upper_dir
        assert upper is not None and upper.exists()

        # Kill shell, copy upper to test dir, then clean up sandbox
        pid = box._persistent_shell.pid
        import shutil
        test_dir = tmp_path / "mapped_copy"
        shutil.copytree(str(upper), str(test_dir))
        os.kill(pid, 9)
        os.waitpid(pid, 0)
        Sandbox.cleanup_stale(str(tmp_path / "envs"))

        # Now test rmtree_mapped on the copy
        if test_dir.exists():
            rmtree_mapped(test_dir)
            assert not test_dir.exists(), "mapped-UID dir should be removed"


# ------------------------------------------------------------------ #
#  Go binary commands: image-layers, image-list                         #
# ------------------------------------------------------------------ #


class TestGoImageCommands:
    """Test image-layers and image-list Go commands."""

    @staticmethod
    def _skip_if_no_gobin():
        from nitrobox._gobin import gobin
        import shutil
        if not shutil.which(gobin()) and not os.path.isfile(gobin()):
            pytest.skip("nitrobox-core Go binary not found")

    @staticmethod
    def _ensure_image(image: str):
        """Ensure image is in containers/storage."""
        from nitrobox.image.layers import _get_store_layers, _containers_storage_pull
        if _get_store_layers(image) is None:
            result = _containers_storage_pull(image)
            assert result, f"failed to pull {image}"

    def test_image_layers(self):
        """ImageLayers returns correct overlay diff paths via Python API."""
        self._skip_if_no_gobin()
        _skip_if_no_registry()
        from nitrobox.image.layers import _get_store_layers

        image = "alpine:latest"
        self._ensure_image(image)

        layers = _get_store_layers(image)
        assert layers is not None, "alpine should be in store"
        assert len(layers) >= 1
        for d in layers:
            assert d.is_dir(), f"layer path not a directory: {d}"
            # Should be an overlay diff directory
            assert "diff" in str(d) or "dir" in str(d)

    def test_image_list(self):
        """_get_store_layers can find images after pull."""
        self._skip_if_no_gobin()
        _skip_if_no_registry()
        from nitrobox.image.layers import _get_store_layers

        image = "alpine:latest"
        self._ensure_image(image)

        # Verify the image is findable by _get_store_layers
        layers = _get_store_layers(image)
        assert layers is not None, "alpine should be in store after pull"
        assert len(layers) >= 1
        # Verify we can read files from the layer
        has_content = any(
            (d / "bin").exists() or (d / "usr").exists()
            for d in layers
        )
        assert has_content, "pulled image has no rootfs content"

    def test_image_layers_nonexistent(self):
        """_get_store_layers returns None for nonexistent image."""
        from nitrobox.image.layers import _get_store_layers

        assert _get_store_layers("nonexistent/image:v999") is None


# ------------------------------------------------------------------ #
#  _containers_storage_root and _get_store_layers edge cases            #
# ------------------------------------------------------------------ #


class TestContainersStorageHelpers:
    """Unit tests for storage helper functions."""

    def test_storage_root_env_override(self, tmp_path, monkeypatch):
        """CONTAINERS_STORAGE_ROOT env var overrides default path."""
        from nitrobox.image.layers import _containers_storage_root

        custom = tmp_path / "custom_store"
        custom.mkdir()
        monkeypatch.setenv("CONTAINERS_STORAGE_ROOT", str(custom))
        assert _containers_storage_root() == custom

    def test_storage_root_default(self, monkeypatch):
        """Without env var, returns ~/.local/share/containers/storage or None."""
        from nitrobox.image.layers import _containers_storage_root

        monkeypatch.delenv("CONTAINERS_STORAGE_ROOT", raising=False)
        result = _containers_storage_root()
        # Either None (dir doesn't exist) or the default path
        if result is not None:
            assert "containers/storage" in str(result)

    def test_get_store_layers_nonexistent_store(self, monkeypatch):
        """_get_store_layers returns None when store doesn't exist."""
        from nitrobox.image.layers import _get_store_layers

        monkeypatch.setenv("CONTAINERS_STORAGE_ROOT", "/tmp/nonexistent_store_12345")
        assert _get_store_layers("alpine:latest") is None

    def test_get_store_layers_name_matching(self):
        """_get_store_layers matches images by name variants."""
        _requires_gobin()
        _skip_if_no_registry()
        from nitrobox.image.layers import _get_store_layers, _containers_storage_pull

        # Ensure alpine is in store
        if _get_store_layers("alpine:latest") is None:
            _containers_storage_pull("alpine:latest")

        # Exact match
        layers = _get_store_layers("alpine:latest")
        assert layers is not None

        # Without :latest tag
        layers2 = _get_store_layers("alpine")
        assert layers2 is not None

    def test_get_store_layers_empty_store(self, tmp_path, monkeypatch):
        """_get_store_layers returns None for empty store directory."""
        from nitrobox.image.layers import _get_store_layers

        empty_store = tmp_path / "empty_store"
        empty_store.mkdir()
        monkeypatch.setenv("CONTAINERS_STORAGE_ROOT", str(empty_store))
        assert _get_store_layers("alpine:latest") is None

    def test_read_config_from_containers_storage(self, tmp_path, monkeypatch):
        """_read_config_from_containers_storage reads WORKDIR/CMD/ENV from OCI config blob."""
        import base64, json
        from nitrobox.image.store import _read_config_from_containers_storage

        # Build a fake containers/storage tree
        store = tmp_path / "store"
        images_dir = store / "overlay-images"
        images_dir.mkdir(parents=True)

        img_id = "abc123def456" * 4 + "00000000"  # 56 chars
        img_id = img_id[:64]

        # Write images.json
        (images_dir / "images.json").write_text(json.dumps([{
            "id": img_id,
            "names": ["localhost/myapp-main:latest"],
            "layer": "somelayer",
        }]))

        # Write OCI config blob in big-data dir
        bd_dir = images_dir / img_id
        bd_dir.mkdir()

        oci_config = {
            "config": {
                "Env": ["PATH=/usr/bin", "FOO=bar"],
                "Cmd": ["/bin/sh"],
                "Entrypoint": ["python", "app.py"],
                "WorkingDir": "/app",
                "ExposedPorts": {"8080/tcp": {}},
            },
            "rootfs": {
                "type": "layers",
                "diff_ids": ["sha256:aaa", "sha256:bbb"],
            },
        }

        # Write manifest pointing to config
        config_digest = f"sha256:{img_id}"
        (bd_dir / "manifest").write_text(json.dumps({
            "config": {"digest": config_digest},
        }))

        # Write config blob with base64-encoded filename
        encoded_name = "=" + base64.b64encode(config_digest.encode()).decode()
        (bd_dir / encoded_name).write_text(json.dumps(oci_config))

        monkeypatch.setenv("CONTAINERS_STORAGE_ROOT", str(store))

        cfg = _read_config_from_containers_storage("localhost/myapp-main:latest")
        assert cfg is not None
        assert cfg["working_dir"] == "/app"
        assert cfg["cmd"] == ["/bin/sh"]
        assert cfg["entrypoint"] == ["python", "app.py"]
        assert cfg["env"] == {"PATH": "/usr/bin", "FOO": "bar"}
        assert cfg["exposed_ports"] == [8080]
        assert cfg["diff_ids"] == ["sha256:aaa", "sha256:bbb"]

    def test_read_config_from_containers_storage_miss(self, tmp_path, monkeypatch):
        """_read_config_from_containers_storage returns None for unknown images."""
        from nitrobox.image.store import _read_config_from_containers_storage

        store = tmp_path / "store"
        images_dir = store / "overlay-images"
        images_dir.mkdir(parents=True)
        (images_dir / "images.json").write_text("[]")

        monkeypatch.setenv("CONTAINERS_STORAGE_ROOT", str(store))
        assert _read_config_from_containers_storage("no-such-image") is None

    def test_read_config_from_containers_storage_no_store(self, monkeypatch):
        """_read_config_from_containers_storage returns None when store doesn't exist."""
        from nitrobox.image.store import _read_config_from_containers_storage

        monkeypatch.setenv("CONTAINERS_STORAGE_ROOT", "/tmp/nonexistent_xyz_99999")
        assert _read_config_from_containers_storage("anything") is None


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
        _requires_gobin()

        async def worker(i):
            config = SandboxConfig(
                image=TEST_IMAGE,
                working_dir="/workspace",
                env_base_dir=str(tmp_path / "envs"),
                rootfs_cache_dir=shared_cache_dir,
            )
            box = Sandbox(config, name=f"async-{i}")
            try:
                out, ec = await box.arun(f"echo worker-{i}")
                assert ec == 0
                assert f"worker-{i}" in out
            finally:
                await box.adelete()

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
        box = Sandbox(config, name="vm-sys")
        try:
            out, ec = box.run("ls /sys/kernel 2>&1")
            assert ec == 0
            assert out.strip(), "/sys/kernel should have contents"
        finally:
            box.delete()

    def test_tmp_writable(self, tmp_path, shared_cache_dir):
        """vm_mode /tmp is writable (stays on overlayfs to preserve image files)."""
        config = SandboxConfig(
            image=TEST_IMAGE,
            vm_mode=True,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="vm-tmp")
        try:
            out, ec = box.run("touch /tmp/test_file && echo ok")
            assert ec == 0
            assert "ok" in out
        finally:
            box.delete()

    def test_run_is_tmpfs(self, tmp_path, shared_cache_dir):
        """vm_mode mounts tmpfs at /run."""
        config = SandboxConfig(
            image=TEST_IMAGE,
            vm_mode=True,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="vm-run")
        try:
            out, ec = box.run("stat -f -c %T /run 2>/dev/null || stat -f /run 2>/dev/null")
            assert ec == 0
            assert "tmpfs" in out.lower(), f"/run should be tmpfs, got: {out}"
        finally:
            box.delete()

    def test_mktemp_works(self, tmp_path, shared_cache_dir):
        """vm_mode sandbox can create temp files (no overlayfs inode overflow)."""
        config = SandboxConfig(
            image=TEST_IMAGE,
            vm_mode=True,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="vm-mktemp")
        try:
            out, ec = box.run("mktemp")
            assert ec == 0
            assert "/tmp/" in out
        finally:
            box.delete()

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
        box = Sandbox(config, name="vm-vol-run")
        try:
            out, ec = box.run("cat /run/scripts/test.sh")
            assert ec == 0
            assert "echo hello" in out
        finally:
            box.delete()

    def test_proc_sys_not_readonly(self, tmp_path, shared_cache_dir):
        """vm_mode does not make /proc/sys read-only."""
        config = SandboxConfig(
            image=TEST_IMAGE,
            vm_mode=True,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        box = Sandbox(config, name="vm-procsys")
        try:
            # In vm_mode, /proc/sys should NOT have a read-only bind mount
            out, ec = box.run("mount 2>/dev/null | grep 'proc/sys.*\\bro\\b' | wc -l")
            assert ec == 0
            count = int(out.strip())
            assert count == 0, f"/proc/sys should not be read-only in vm_mode, found {count} ro mounts"
        finally:
            box.delete()

