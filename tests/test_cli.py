"""Tests for the nitrobox CLI."""

from __future__ import annotations

import os
import subprocess
import time

import pytest

from nitrobox import Sandbox, SandboxConfig

TEST_IMAGE = os.environ.get("LITE_SANDBOX_TEST_IMAGE", "ubuntu:22.04")


def _skip_if_root():
    if os.geteuid() == 0:
        pytest.skip("CLI tests must run as non-root")


def _requires_docker():
    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        pytest.skip("requires Docker")


def _nbx(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["python", "-m", "nitrobox.cli", *args],
        capture_output=True, text=True, timeout=10,
    )


class TestCli:
    def test_ps_empty(self):
        """ps should work with no sandboxes."""
        _skip_if_root()
        result = _nbx("ps")
        assert result.returncode == 0
        assert "No sandboxes" in result.stdout or "NAME" in result.stdout

    def test_cleanup_empty(self):
        """cleanup should work with nothing to clean."""
        _skip_if_root()
        result = _nbx("cleanup")
        assert result.returncode == 0
        assert "No stale" in result.stdout or "Cleaned up" in result.stdout

    def test_kill_nonexistent(self):
        """kill should error on unknown sandbox."""
        _skip_if_root()
        result = _nbx("kill", "nonexistent-sandbox-xyz")
        assert result.returncode != 0
        assert "not found" in result.stderr

    def test_no_args_shows_help(self):
        """No subcommand should show help."""
        _skip_if_root()
        result = _nbx()
        assert result.returncode == 0
        assert "usage" in result.stdout.lower() or "ps" in result.stdout

    def test_cleanup_orphaned_dir(self, tmp_path):
        """cleanup should remove dirs with work/ but no .pid file."""
        _skip_if_root()
        env_dir = str(tmp_path / "envs")
        # Simulate orphaned sandbox dir (partial atexit cleanup)
        orphan = tmp_path / "envs" / "orphan-sandbox"
        (orphan / "work" / "work").mkdir(parents=True)
        (orphan / "work" / "work").chmod(0o000)
        (orphan / "upper").mkdir()

        result = _nbx("--dir", env_dir, "cleanup")
        assert result.returncode == 0
        assert not orphan.exists(), f"orphan dir not cleaned: {list(orphan.rglob('*'))}"

    def test_kill_all(self, tmp_path, shared_cache_dir):
        """kill --all should kill all sandbox shells without killing us."""
        _skip_if_root()
        _requires_docker()
        env_dir = str(tmp_path / "envs")

        sandboxes = []
        for name in ("kill-all-1", "kill-all-2"):
            sb = Sandbox(SandboxConfig(
                image=TEST_IMAGE,
                env_base_dir=env_dir,
                rootfs_cache_dir=shared_cache_dir,
            ), name=name)
            sandboxes.append(sb)

        result = _nbx("--dir", env_dir, "ps")
        assert "kill-all-1" in result.stdout
        assert "kill-all-2" in result.stdout

        result = _nbx("--dir", env_dir, "kill", "--all")
        assert result.returncode == 0

        result = _nbx("--dir", env_dir, "ps")
        assert "No sandboxes" in result.stdout

    def test_ps_shows_running_sandbox(self, tmp_path, shared_cache_dir):
        """ps should list a running sandbox."""
        _skip_if_root()
        _requires_docker()
        env_dir = str(tmp_path / "envs")
        sb = Sandbox(SandboxConfig(
            image=TEST_IMAGE,
            env_base_dir=env_dir,
            rootfs_cache_dir=shared_cache_dir,
        ), name="cli-ps-test")
        try:
            result = _nbx("--dir", env_dir, "ps")
            assert result.returncode == 0
            assert "cli-ps-test" in result.stdout
            assert "running" in result.stdout
        finally:
            sb.delete()

    def test_kill_and_cleanup(self, tmp_path, shared_cache_dir):
        """kill should terminate the sandbox shell and clean up the dir."""
        _skip_if_root()
        _requires_docker()
        env_dir = str(tmp_path / "envs")

        # Create sandbox in subprocess
        proc = subprocess.Popen(
            [
                "python", "-c",
                f"from nitrobox import Sandbox, SandboxConfig; "
                f"import time; "
                f"sb = Sandbox(SandboxConfig(image='{TEST_IMAGE}', "
                f"env_base_dir='{env_dir}', "
                f"rootfs_cache_dir='{shared_cache_dir}'), "
                f"name='cli-kill-test'); "
                f"time.sleep(60)",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(2)

        try:
            result = _nbx("--dir", env_dir, "ps")
            assert "cli-kill-test" in result.stdout

            # nitrobox kill targets the shell process, not the owner
            result = _nbx("--dir", env_dir, "kill", "cli-kill-test")
            assert result.returncode == 0
            assert "killed" in result.stdout

            # Dir should be cleaned by kill's auto-cleanup
            import pathlib
            env_path = pathlib.Path(env_dir)
            assert not (env_path / "cli-kill-test").exists(), (
                f"sandbox dir not cleaned: {list((env_path / 'cli-kill-test').rglob('*'))}"
            )

            # Owner subprocess should still be alive (only shell was killed)
            assert proc.poll() is None, "owner process should not be killed"
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()

    def test_kill_from_owner_process(self, tmp_path, shared_cache_dir):
        """nitrobox kill from the sandbox owner process should not kill itself."""
        _skip_if_root()
        _requires_docker()
        env_dir = str(tmp_path / "envs")

        sb = Sandbox(SandboxConfig(
            image=TEST_IMAGE,
            env_base_dir=env_dir,
            rootfs_cache_dir=shared_cache_dir,
        ), name="kill-self-test")

        result = _nbx("--dir", env_dir, "ps")
        assert "kill-self-test" in result.stdout

        # nitrobox kill should kill the shell, not us
        result = _nbx("--dir", env_dir, "kill", "kill-self-test")
        assert result.returncode == 0

        # We're still alive — the test process wasn't killed
        # Sandbox is now broken (shell dead) but we can still clean up
        try:
            sb.delete()
        except Exception:
            pass  # shell already dead, delete may partially fail
        # cleanup_stale handles the rest
        Sandbox.cleanup_stale(env_dir)
