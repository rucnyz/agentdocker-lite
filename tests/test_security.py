"""Tests for security hardening: seccomp, user namespace mode, devices.

seccomp tests require root. User namespace tests must run as non-root.

Run with: sudo python -m pytest tests/test_security.py -v
"""

from __future__ import annotations

import os
import subprocess

import pytest

from agentdocker_lite import Sandbox, SandboxBase, SandboxConfig

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
def root_sandbox(tmp_path, shared_cache_dir):
    """Standard root sandbox with seccomp enabled (default)."""
    _requires_root()
    _requires_docker()
    config = SandboxConfig(
        image=TEST_IMAGE,
        working_dir="/workspace",
        env_base_dir=str(tmp_path / "envs"),
        rootfs_cache_dir=shared_cache_dir,
        seccomp=True,
    )
    sb = Sandbox(config, name="sec-test")
    yield sb
    sb.delete()


@pytest.fixture
def userns_sandbox(tmp_path, shared_cache_dir):
    """User namespace sandbox — skipped if running as root."""
    if os.geteuid() == 0:
        pytest.skip("userns test must run as non-root")
    _requires_docker()
    config = SandboxConfig(
        image=TEST_IMAGE,
        working_dir="/workspace",
        env_base_dir=str(tmp_path / "envs"),
        rootfs_cache_dir=shared_cache_dir,
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

    def test_seccomp_filter_active(self, root_sandbox):
        """Seccomp filter is active (applied via static binary, no Python needed)."""
        output, ec = root_sandbox.run("cat /proc/self/status | grep Seccomp")
        assert ec == 0
        assert "2" in output  # Seccomp: 2 = filter mode

    def test_mount_blocked(self, root_sandbox):
        """mount(2) should be blocked by seccomp."""
        output, ec = root_sandbox.run("mount -t tmpfs tmpfs /tmp 2>&1")
        assert ec != 0
        assert "denied" in output.lower() or "not permitted" in output.lower()

    def test_unshare_blocked(self, root_sandbox):
        """unshare(2) should be blocked — prevents namespace escape."""
        output, ec = root_sandbox.run("unshare --pid echo escape 2>&1")
        assert ec != 0

    def test_clone_ns_flags_blocked(self, root_sandbox):
        """clone(2) with namespace flags should be blocked."""
        # nsenter requires clone with CLONE_NEWPID — should fail
        output, ec = root_sandbox.run("unshare --mount echo test 2>&1")
        assert ec != 0

    def test_capabilities_dropped(self, root_sandbox):
        """Non-default capabilities should be dropped."""
        # CAP_SYS_ADMIN (21) should NOT be in bounding set
        output, ec = root_sandbox.run("cat /proc/self/status | grep CapBnd")
        assert ec == 0
        cap_hex = output.strip().split()[-1]
        cap_val = int(cap_hex, 16)
        assert not (cap_val & (1 << 21)), "CAP_SYS_ADMIN should be dropped"
        # CAP_NET_ADMIN (12) should NOT be in bounding set
        assert not (cap_val & (1 << 12)), "CAP_NET_ADMIN should be dropped"
        # CAP_CHOWN (0) should still be present (Docker default)
        assert cap_val & (1 << 0), "CAP_CHOWN should be kept"


# ------------------------------------------------------------------ #
#  Cleanup                                                              #
# ------------------------------------------------------------------ #


class TestCleanup:
    """Verify stale resource cleanup."""

    def test_cleanup_stale_no_crash(self, tmp_path):
        """cleanup_stale() should not crash even with nothing to clean."""
        _requires_root()
        SandboxBase.cleanup_stale(str(tmp_path / "envs"))

    def test_cleanup_stale_removes_leftover(self, tmp_path, shared_cache_dir):
        """cleanup_stale() removes leftover sandbox directories."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="stale-test")
        env_dir = tmp_path / "envs" / "stale-test"
        assert env_dir.exists()
        # Properly delete — this unmounts and kills the process
        sb.delete()
        # Recreate env dir with .pid pointing to a dead PID to simulate stale
        env_dir.mkdir(parents=True, exist_ok=True)
        (env_dir / ".pid").write_text("999999999")
        (env_dir / "rootfs").mkdir(exist_ok=True)
        # cleanup_stale should remove the stale directory
        cleaned = SandboxBase.cleanup_stale(str(tmp_path / "envs"))
        assert cleaned >= 1
        assert not env_dir.exists()


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

    def test_dns_resolv_conf(self, userns_sandbox):
        """DNS resolv.conf should be propagated from host."""
        output, ec = userns_sandbox.run("cat /etc/resolv.conf")
        assert ec == 0
        # Should contain at least one nameserver entry
        assert "nameserver" in output

    def test_tmp_writable(self, userns_sandbox):
        """Any user should be able to write to /tmp (mode 1777)."""
        output, ec = userns_sandbox.run("stat -c %a /tmp")
        assert ec == 0
        assert output.strip() == "1777"

    def test_devpts_mounted(self, userns_sandbox):
        """/dev/pts should be mounted (needed for PTY allocation)."""
        output, ec = userns_sandbox.run("test -d /dev/pts && echo ok")
        assert ec == 0
        assert "ok" in output

    def test_full_uid_mapping(self, userns_sandbox):
        """If subuid is configured, multiple UIDs should be mapped."""
        output, ec = userns_sandbox.run("cat /proc/self/uid_map")
        assert ec == 0
        lines = [l.strip() for l in output.strip().splitlines() if l.strip()]
        # Full mapping has 2+ lines; fallback has 1 line
        if len(lines) > 1:
            # Verify uid 0 is mapped and there's a range mapping
            assert any(l.startswith("0") for l in lines)
        # Either way, uid 0 should work
        output2, ec2 = userns_sandbox.run("id -u")
        assert ec2 == 0
        assert output2.strip() == "0"

    def test_layer_cache_enabled(self, userns_sandbox):
        """Rootless mode should use layer cache (not flat rootfs)."""
        features = userns_sandbox.features
        assert features.get("layer_cache") is True

    def test_whiteout_strategy(self, userns_sandbox):
        """Whiteout strategy should be detected based on kernel version."""
        from agentdocker_lite.rootfs import _detect_whiteout_strategy
        strategy = _detect_whiteout_strategy()
        assert strategy in ("xattr", "userns")
        assert userns_sandbox.features.get("whiteout") == strategy

    def test_multi_layer_image(self, tmp_path, shared_cache_dir):
        """Multi-layer image (python:3.11-slim, 4+ layers) works in rootless."""
        if os.geteuid() == 0:
            pytest.skip("userns test must run as non-root")
        _requires_docker()
        config = SandboxConfig(
            image="python:3.11-slim",
            working_dir="/tmp",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-multi-layer")
        try:
            assert sb._layer_dirs is not None
            assert len(sb._layer_dirs) >= 4
            output, ec = sb.run("python3 --version")
            assert ec == 0
            assert "3.11" in output
        finally:
            sb.delete()

    def test_shared_layers_rootless(self, tmp_path, shared_cache_dir):
        """Two images sharing base layers reuse cached layers in rootless."""
        if os.geteuid() == 0:
            pytest.skip("userns test must run as non-root")
        _requires_docker()
        sandboxes = []
        for i, img in enumerate(["python:3.11-slim", "python:3.12-slim"]):
            config = SandboxConfig(
                image=img,
                working_dir="/tmp",
                env_base_dir=str(tmp_path / "envs"),
                rootfs_cache_dir=shared_cache_dir,
            )
            sandboxes.append(Sandbox(config, name=f"userns-layer-{i}"))
        try:
            layers0 = set(l.name for l in (sandboxes[0]._layer_dirs or []))
            layers1 = set(l.name for l in (sandboxes[1]._layer_dirs or []))
            shared = layers0 & layers1
            assert len(shared) > 0, "python 3.11 and 3.12 should share base layers"
        finally:
            for sb in sandboxes:
                sb.delete()

    def test_read_only_rootfs(self, tmp_path, shared_cache_dir):
        """Read-only rootfs works in userns mode."""
        if os.geteuid() == 0:
            pytest.skip("userns test must run as non-root")
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            read_only=True,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-ro")
        try:
            _, ec = sb.run("touch /test_ro 2>/dev/null")
            assert ec != 0, "write should fail on read-only rootfs"
            # /dev/null should still work (mounted on top)
            _, ec = sb.run("echo x > /dev/null")
            assert ec == 0
        finally:
            sb.delete()

    def test_volume_rw(self, tmp_path, shared_cache_dir):
        """Read-write volume works in userns mode."""
        if os.geteuid() == 0:
            pytest.skip("userns test must run as non-root")
        _requires_docker()
        shared = tmp_path / "shared"
        shared.mkdir()
        (shared / "input.txt").write_text("from host")

        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            volumes=[f"{shared}:/mnt/data:rw"],
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-vol-rw")
        try:
            output, ec = sb.run("cat /mnt/data/input.txt")
            assert ec == 0
            assert "from host" in output
            sb.run("echo from_sandbox > /mnt/data/output.txt")
            assert (shared / "output.txt").read_text().strip() == "from_sandbox"
        finally:
            sb.delete()

    def test_volume_ro(self, tmp_path, shared_cache_dir):
        """Read-only volume works in userns mode."""
        if os.geteuid() == 0:
            pytest.skip("userns test must run as non-root")
        _requires_docker()
        shared = tmp_path / "shared"
        shared.mkdir()
        (shared / "data.txt").write_text("read only")

        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            volumes=[f"{shared}:/mnt/data:ro"],
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-vol-ro")
        try:
            output, ec = sb.run("cat /mnt/data/data.txt")
            assert ec == 0
            assert "read only" in output
            _, ec = sb.run("echo x > /mnt/data/data.txt 2>&1")
            assert ec != 0, "write should fail on ro volume"
        finally:
            sb.delete()

    def test_hostname(self, tmp_path, shared_cache_dir):
        """Custom hostname works in userns mode."""
        if os.geteuid() == 0:
            pytest.skip("userns test must run as non-root")
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            hostname="userns-box",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-hostname")
        try:
            output, ec = sb.run("hostname")
            assert ec == 0
            assert "userns-box" in output.strip()
        finally:
            sb.delete()


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

    def test_device_passthrough(self, tmp_path, shared_cache_dir):
        """Passed-through device should be accessible."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            devices=["/dev/null"],  # /dev/null exists on all Linux
        )
        sb = Sandbox(config, name="dev-test")
        try:
            output, ec = sb.run("test -e /dev/null && echo exists")
            assert ec == 0
            assert "exists" in output
        finally:
            sb.delete()


# ------------------------------------------------------------------ #
#  Masked / read-only paths and OOM score                              #
# ------------------------------------------------------------------ #


class TestHardening:
    """Verify default security hardening (mask, readonly, oom, cpuset)."""

    def test_masked_paths(self, root_sandbox):
        """Sensitive paths should be masked (empty or inaccessible)."""
        # /proc/kcore is bound to /dev/null — reading returns empty
        output, ec = root_sandbox.run("cat /proc/kcore 2>&1 | wc -c")
        assert ec == 0
        assert int(output.strip()) == 0

    def test_readonly_paths(self, root_sandbox):
        """Kernel tunable paths should be read-only."""
        output, ec = root_sandbox.run("touch /proc/sys/kernel/hostname 2>&1")
        # Should fail with permission error or read-only error
        assert ec != 0

    def test_oom_score_adj(self, tmp_path, shared_cache_dir):
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            oom_score_adj=500,
        )
        sb = Sandbox(config, name="oom-test")
        try:
            pid = sb._persistent_shell._process.pid
            score = open(f"/proc/{pid}/oom_score_adj").read().strip()
            assert score == "500"
        finally:
            sb.delete()

    def test_cpuset(self, tmp_path, shared_cache_dir):
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            cpuset_cpus="0",
        )
        sb = Sandbox(config, name="cpuset-test")
        try:
            output, ec = sb.run("echo ok")
            assert ec == 0
            assert "ok" in output
        finally:
            sb.delete()
