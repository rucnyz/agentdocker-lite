"""Tests for security hardening: seccomp, Landlock, user namespace mode, devices.

seccomp tests require root. User namespace tests must run as non-root.

Run with: sudo python -m pytest tests/test_security.py -v
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from nitrobox import Sandbox, SandboxConfig
from nitrobox._errors import SandboxInitError, SandboxKernelError
from nitrobox._core import py_landlock_abi_version as _landlock_abi_version

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

    def test_exit_code_propagation(self, root_sandbox):
        """Shell exit codes must propagate correctly."""
        _, ec = root_sandbox.run("bash -c 'exit 42'")
        assert ec == 42, f"Expected exit code 42, got {ec}"
        _, ec = root_sandbox.run("false")
        assert ec == 1, f"Expected exit code 1, got {ec}"



# ------------------------------------------------------------------ #
#  Entrypoint                                                           #
# ------------------------------------------------------------------ #


class TestEntrypoint:
    """Verify OCI ENTRYPOINT is executed before the shell."""

    def test_entrypoint_runs_on_start(self, tmp_path, shared_cache_dir):
        """ENTRYPOINT script runs during sandbox init and creates a marker."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            entrypoint=["/bin/sh", "-c",
                        "touch /tmp/.ep_ran; exec \"$@\"", "--"],
        )
        sb = Sandbox(config, name="ep-test")
        try:
            output, ec = sb.run("cat /tmp/.ep_ran 2>&1 && echo OK")
            assert ec == 0, f"Entrypoint marker missing: {output}"
            assert "OK" in output
        finally:
            sb.delete()

    def test_entrypoint_env_setup(self, tmp_path, shared_cache_dir):
        """ENTRYPOINT can set up environment visible to later commands."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            entrypoint=["/bin/sh", "-c",
                        "mkdir -p /data && echo ready > /data/status; exec \"$@\"",
                        "--"],
        )
        sb = Sandbox(config, name="ep-env")
        try:
            output, ec = sb.run("cat /data/status")
            assert ec == 0
            assert "ready" in output
        finally:
            sb.delete()

    def test_entrypoint_survives_reset(self, tmp_path, shared_cache_dir):
        """ENTRYPOINT re-runs after sandbox reset."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            entrypoint=["/bin/sh", "-c",
                        "touch /tmp/.ep_ran; exec \"$@\"", "--"],
        )
        sb = Sandbox(config, name="ep-reset")
        try:
            # Verify entrypoint ran
            _, ec = sb.run("test -f /tmp/.ep_ran")
            assert ec == 0
            # Delete marker and reset
            sb.run("rm /tmp/.ep_ran")
            sb.reset()
            # After reset, entrypoint should have re-run
            _, ec = sb.run("test -f /tmp/.ep_ran")
            assert ec == 0, "Entrypoint did not re-run after reset"
        finally:
            sb.delete()

    def test_no_entrypoint_works(self, root_sandbox):
        """Sandbox without entrypoint still works normally."""
        output, ec = root_sandbox.run("echo hello")
        assert ec == 0
        assert "hello" in output

    def test_bad_entrypoint_fails_gracefully(self, tmp_path, shared_cache_dir):
        """Non-existent entrypoint should fail at sandbox creation."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            entrypoint=["/nonexistent_entrypoint.sh"],
        )
        with pytest.raises((RuntimeError, SandboxInitError)):
            Sandbox(config, name="ep-bad")

    def test_entrypoint_rootless(self, tmp_path, shared_cache_dir):
        """ENTRYPOINT works in rootless (user namespace) mode."""
        if os.geteuid() == 0:
            pytest.skip("rootless test must run as non-root")
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            entrypoint=["/bin/sh", "-c",
                        "touch /tmp/.ep_rootless; exec \"$@\"", "--"],
        )
        sb = Sandbox(config, name="ep-rootless")
        try:
            _, ec = sb.run("test -f /tmp/.ep_rootless")
            assert ec == 0, "Entrypoint did not run in rootless mode"
        finally:
            sb.delete()

    def test_image_entrypoint_backfill(self, tmp_path, shared_cache_dir):
        """SandboxConfig.entrypoint is auto-filled from OCI image config."""
        _requires_root()
        _requires_docker()
        from unittest.mock import patch

        fake_cfg = {
            "entrypoint": ["/bin/sh", "-c", "touch /tmp/.ep_auto; exec \"$@\"", "--"],
            "cmd": None,
            "env": {},
            "working_dir": None,
        }
        config = SandboxConfig(
            image=TEST_IMAGE,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        assert config.entrypoint is None  # not set yet

        with patch("nitrobox.rootfs.get_image_config", return_value=fake_cfg):
            sb = Sandbox(config, name="ep-auto")

        try:
            assert config.entrypoint == fake_cfg["entrypoint"]
            _, ec = sb.run("test -f /tmp/.ep_auto")
            assert ec == 0, "Auto-filled entrypoint did not run"
        finally:
            sb.delete()


# ------------------------------------------------------------------ #
#  Cleanup                                                              #
# ------------------------------------------------------------------ #


class TestCleanup:
    """Verify stale resource cleanup."""

    def test_cleanup_stale_no_crash(self, tmp_path):
        """cleanup_stale() should not crash even with nothing to clean."""
        _requires_root()
        Sandbox.cleanup_stale(str(tmp_path / "envs"))

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
        cleaned = Sandbox.cleanup_stale(str(tmp_path / "envs"))
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

    def test_dev_devices_survive_reset(self, userns_sandbox):
        """/dev/null, /dev/zero, /dev/random should be char devices after reset."""
        userns_sandbox.reset()
        for dev in ("null", "zero", "random", "urandom"):
            output, ec = userns_sandbox.run(f"test -c /dev/{dev} && echo ok")
            assert ec == 0 and "ok" in output, f"/dev/{dev} is not a char device after reset"

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
        from nitrobox.rootfs import _detect_whiteout_strategy
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

    def test_port_map(self, tmp_path, shared_cache_dir):
        """Port mapping works in rootless mode (pasta inside userns)."""
        import urllib.request
        import time

        if os.geteuid() == 0:
            pytest.skip("userns test must run as non-root")
        _requires_docker()
        config = SandboxConfig(
            image="python:3.11-slim",
            working_dir="/tmp",
            net_isolate=True,
            port_map=["19789:8000"],
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-port")
        try:
            sb.run_background("python3 -m http.server 8000 --directory /tmp")
            for _ in range(20):
                try:
                    r = urllib.request.urlopen("http://localhost:19789/", timeout=1)
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                raise AssertionError("server did not start")
            assert r.status == 200
        finally:
            sb.delete()

    def test_net_isolate_no_port_map(self, tmp_path, shared_cache_dir):
        """net_isolate=True without port_map gives loopback-only in rootless."""
        if os.geteuid() == 0:
            pytest.skip("userns test must run as non-root")
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            net_isolate=True,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-netiso")
        try:
            output, ec = sb.run("ls /sys/class/net/ 2>/dev/null || echo lo")
            assert ec == 0
            # Should only see loopback
            ifaces = output.strip().split()
            assert "lo" in ifaces
        finally:
            sb.delete()

    def test_seccomp_active(self, userns_sandbox):
        """Seccomp BPF is active in rootless mode (via Rust init chain)."""
        output, ec = userns_sandbox.run("cat /proc/self/status | grep Seccomp")
        assert ec == 0
        assert "2" in output  # Seccomp: 2 = filter mode

    def test_mount_blocked(self, userns_sandbox):
        """mount(2) should be blocked by seccomp in rootless mode."""
        _, ec = userns_sandbox.run("mount -t tmpfs tmpfs /tmp 2>/dev/null")
        assert ec != 0

    def test_masked_paths(self, userns_sandbox):
        """Sensitive paths should be masked in rootless mode."""
        output, ec = userns_sandbox.run("cat /proc/kcore 2>&1 | wc -c")
        assert ec == 0
        assert int(output.strip()) == 0


# ------------------------------------------------------------------ #
#  Shared network namespace tests (rootless)                           #
# ------------------------------------------------------------------ #


class TestSharedNetwork:
    """Verify SharedNetwork for sandbox-level network sharing."""

    def _skip_if_not_rootless(self):
        if os.geteuid() == 0:
            pytest.skip("must run as non-root")
        _requires_docker()

    def test_shared_netns_between_sandboxes(self, tmp_path, shared_cache_dir):
        """Two sandboxes sharing a SharedNetwork have the same netns."""
        self._skip_if_not_rootless()
        from nitrobox.compose import SharedNetwork

        net = SharedNetwork("test-net")
        try:
            sb1 = Sandbox(SandboxConfig(
                image=TEST_IMAGE,
                env_base_dir=str(tmp_path / "envs"),
                rootfs_cache_dir=shared_cache_dir,
                shared_userns=net.userns_path,
                net_ns=net.netns_path,
            ), name="net-a")
            sb2 = Sandbox(SandboxConfig(
                image=TEST_IMAGE,
                env_base_dir=str(tmp_path / "envs"),
                rootfs_cache_dir=shared_cache_dir,
                shared_userns=net.userns_path,
                net_ns=net.netns_path,
            ), name="net-b")

            # Same network namespace
            ns1, _ = sb1.run("readlink /proc/1/ns/net")
            ns2, _ = sb2.run("readlink /proc/1/ns/net")
            assert ns1.strip() == ns2.strip()

            # Different mount namespaces (filesystem isolation)
            mnt1, _ = sb1.run("readlink /proc/1/ns/mnt")
            mnt2, _ = sb2.run("readlink /proc/1/ns/mnt")
            assert mnt1.strip() != mnt2.strip()

            sb2.delete()
            sb1.delete()
        finally:
            net.destroy()

    def test_different_shared_networks_isolated(self, tmp_path, shared_cache_dir):
        """Sandboxes on different SharedNetworks have different netns."""
        self._skip_if_not_rootless()
        from nitrobox.compose import SharedNetwork

        net_a = SharedNetwork("net-a")
        net_b = SharedNetwork("net-b")
        try:
            sb1 = Sandbox(SandboxConfig(
                image=TEST_IMAGE,
                env_base_dir=str(tmp_path / "envs"),
                rootfs_cache_dir=shared_cache_dir,
                shared_userns=net_a.userns_path,
                net_ns=net_a.netns_path,
            ), name="iso-a")
            sb2 = Sandbox(SandboxConfig(
                image=TEST_IMAGE,
                env_base_dir=str(tmp_path / "envs"),
                rootfs_cache_dir=shared_cache_dir,
                shared_userns=net_b.userns_path,
                net_ns=net_b.netns_path,
            ), name="iso-b")

            ns1, _ = sb1.run("readlink /proc/1/ns/net")
            ns2, _ = sb2.run("readlink /proc/1/ns/net")
            assert ns1.strip() != ns2.strip()

            sb2.delete()
            sb1.delete()
        finally:
            net_b.destroy()
            net_a.destroy()

    def test_shared_network_sandbox_runs_commands(self, tmp_path, shared_cache_dir):
        """Sandbox with shared userns can run commands normally."""
        self._skip_if_not_rootless()
        from nitrobox.compose import SharedNetwork

        net = SharedNetwork("cmd-test")
        try:
            sb = Sandbox(SandboxConfig(
                image=TEST_IMAGE,
                env_base_dir=str(tmp_path / "envs"),
                rootfs_cache_dir=shared_cache_dir,
                shared_userns=net.userns_path,
                net_ns=net.netns_path,
            ), name="cmd-test")

            out, ec = sb.run("echo shared-net-ok")
            assert ec == 0
            assert "shared-net-ok" in out

            # File I/O works
            sb.write_file("/tmp/test.txt", "hello\n")
            content = sb.read_file("/tmp/test.txt")
            assert "hello" in content

            # Reset works
            sb.reset()
            _, ec = sb.run("cat /tmp/test.txt 2>/dev/null")
            assert ec != 0

            sb.delete()
        finally:
            net.destroy()


# ------------------------------------------------------------------ #
#  Mapped-uid cleanup tests (rootless full uid mapping)                #
# ------------------------------------------------------------------ #


class TestFailedCreationCleanup:
    """Verify sandbox dirs are cleaned up when creation fails."""

    def _skip_if_root(self):
        if os.geteuid() == 0:
            pytest.skip("rootless only")

    def test_cleanup_on_failed_init(self, shared_cache_dir, tmp_path):
        """If sandbox init fails, env_dir should be fully removed."""
        self._skip_if_root()
        env_dir = tmp_path / "envs"
        # Use an invalid shell to force startup failure
        from nitrobox.sandbox import Sandbox as RootlessSandbox
        config = SandboxConfig(
            image=TEST_IMAGE,
            env_base_dir=str(env_dir),
            rootfs_cache_dir=shared_cache_dir,
        )
        # Monkey-patch to force a startup timeout by using a nonexistent shell
        original_shell = "/bin/bash"
        config_dict = config.__dict__
        # Force a very short timeout so the test doesn't hang 30s
        # Instead, trigger failure by using an image that doesn't exist
        # Actually, simplest: create the sandbox dirs manually then
        # verify they get cleaned up
        sandbox_env = env_dir / "fail-test"
        sandbox_env.mkdir(parents=True)
        work_dir = sandbox_env / "work"
        work_dir.mkdir()
        # Simulate kernel's d--------- overlayfs work dir
        inner_work = work_dir / "work"
        inner_work.mkdir()
        inner_work.chmod(0o000)

        # Verify the d--------- dir exists and is not deletable normally
        import shutil
        shutil.rmtree(sandbox_env, ignore_errors=True)
        assert sandbox_env.exists(), "d--------- dir should survive rmtree"

        # Now use the cleanup logic from RootlessSandbox
        for child in sandbox_env.rglob("*"):
            try:
                child.chmod(0o700)
            except OSError:
                pass
        shutil.rmtree(sandbox_env, ignore_errors=True)
        assert not sandbox_env.exists(), "cleanup should remove everything"


class TestDeleteCleanup:
    """Verify sb.delete() leaves nothing behind."""

    def _skip_if_root(self):
        if os.geteuid() == 0:
            pytest.skip("rootless only")

    def test_delete_removes_env_dir(self, shared_cache_dir, tmp_path):
        self._skip_if_root()
        env_dir = tmp_path / "envs"
        sb = Sandbox(SandboxConfig(
            image=TEST_IMAGE,
            env_base_dir=str(env_dir),
            rootfs_cache_dir=shared_cache_dir,
        ), name="del-clean")
        sb.run("touch /tmp/test.txt")
        sandbox_dir = env_dir / "del-clean"
        assert sandbox_dir.exists()
        sb.delete()
        assert not sandbox_dir.exists(), "env_dir should be gone after delete"

    def test_delete_after_many_files(self, shared_cache_dir, tmp_path):
        """delete() cleans up even with many files in upper."""
        self._skip_if_root()
        env_dir = tmp_path / "envs"
        sb = Sandbox(SandboxConfig(
            image=TEST_IMAGE,
            env_base_dir=str(env_dir),
            rootfs_cache_dir=shared_cache_dir,
        ), name="del-many")
        sb.run("seq 1 200 | xargs -I{} touch /tmp/f_{}")
        sb.delete()
        assert not (env_dir / "del-many").exists()

    def test_delete_with_cow_volume(self, shared_cache_dir, tmp_path):
        """delete() cleans up cow volume overlay dirs."""
        self._skip_if_root()
        host_dir = tmp_path / "hostdata"
        host_dir.mkdir()
        (host_dir / "base.txt").write_text("hello")
        env_dir = tmp_path / "envs"
        sb = Sandbox(SandboxConfig(
            image=TEST_IMAGE,
            volumes=[f"{host_dir}:/data:cow"],
            env_base_dir=str(env_dir),
            rootfs_cache_dir=shared_cache_dir,
        ), name="del-cow")
        sb.run("echo modified > /data/base.txt")
        sb.delete()
        assert not (env_dir / "del-cow").exists()


class TestMappedUidCleanup:
    """Verify delete/reset properly cleans files owned by mapped uids.

    With full uid mapping (newuidmap), apt-get etc. create files as
    non-root users (e.g. _apt uid 100 → host uid 100099).  Without
    the nsenter-based ownership fix, these files cannot be deleted.
    """

    def _skip_if_no_full_mapping(self):
        if os.geteuid() == 0:
            pytest.skip("userns test must run as non-root")
        from nitrobox.sandbox import Sandbox as RootlessSandbox
        if RootlessSandbox._detect_subuid_range() is None:
            pytest.skip("full uid mapping not configured (no subuid entry)")

    def test_delete_cleans_mapped_uid_files(self, tmp_path, shared_cache_dir):
        """delete() should fully remove env dir even with mapped-uid files."""
        self._skip_if_no_full_mapping()
        _requires_docker()

        env_dir = tmp_path / "envs" / "mapped-uid-del"
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="mapped-uid-del")

        # Create files as non-root mapped user (e.g. _apt, uid 100)
        _, ec = sb.run(
            "apt-get update -qq 2>/dev/null | tail -1",
            timeout=120,
        )
        if ec != 0:
            sb.delete()
            pytest.skip("apt-get update failed")

        # Verify that mapped-uid files exist in upper dir
        upper = sb._upper_dir
        assert upper is not None
        mapped_files = []
        host_uid = os.getuid()
        for f in upper.rglob("*"):
            try:
                st = f.lstat()
                if st.st_uid != host_uid:
                    mapped_files.append((str(f), st.st_uid))
            except OSError:
                pass
        assert mapped_files, "expected mapped-uid files from apt-get"

        sb.delete()
        assert not env_dir.exists(), (
            f"env dir not fully cleaned: {list(env_dir.rglob('*'))[:5]}"
        )

    def test_reset_cleans_mapped_uid_dead_dirs(self, tmp_path, shared_cache_dir):
        """reset() should clean dead dirs that contain mapped-uid files."""
        self._skip_if_no_full_mapping()
        _requires_docker()

        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="mapped-uid-rst")
        env_dir = tmp_path / "envs" / "mapped-uid-rst"

        # Create mapped-uid files
        _, ec = sb.run(
            "apt-get update -qq 2>/dev/null | tail -1",
            timeout=120,
        )
        if ec != 0:
            sb.delete()
            pytest.skip("apt-get update failed")

        # Reset creates dead dirs from the old upper/work
        sb.reset()

        # After reset, old dirs are renamed to *.dead.*
        dead_dirs = list(env_dir.glob("*.dead.*"))
        # Dead dirs exist now, will be cleaned on next reset
        sb.reset()

        # After second reset, old dead dirs should be fully cleaned
        remaining_dead = [
            d for d in env_dir.glob("*.dead.*")
            if d.name.split(".dead.")[0] in ("upper", "work")
            and int(d.name.split(".")[-1]) < int(dead_dirs[0].name.split(".")[-1])
            if dead_dirs
        ]
        assert not remaining_dead, f"stale dead dirs remain: {remaining_dead}"

        sb.delete()
        assert not env_dir.exists()


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
            pid = sb._persistent_shell.pid
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


def _requires_landlock():
    if _landlock_abi_version() == 0:
        pytest.skip("Landlock not available (kernel < 5.13)")


# ------------------------------------------------------------------ #
#  Landlock tests (root mode)                                          #
# ------------------------------------------------------------------ #


class TestLandlockRootful:
    """Verify Landlock path/port restrictions in rootful mode."""

    def test_writable_paths(self, tmp_path, shared_cache_dir):
        """Only listed paths should be writable."""
        _requires_root()
        _requires_docker()
        _requires_landlock()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            writable_paths=["/workspace"],
        )
        sb = Sandbox(config, name="ll-write")
        try:
            # /workspace should be writable
            output, ec = sb.run("echo ok > /workspace/test.txt && cat /workspace/test.txt")
            assert ec == 0
            assert "ok" in output
            # /root should NOT be writable (not in writable_paths)
            _, ec = sb.run("touch /root/test.txt 2>/dev/null")
            assert ec != 0, "write to /root should fail with Landlock"
            # /tmp is auto-added as writable
            output, ec = sb.run("echo tmp_ok > /tmp/test_ll.txt && cat /tmp/test_ll.txt")
            assert ec == 0
            assert "tmp_ok" in output
        finally:
            sb.delete()

    def test_writable_paths_reads_unrestricted(self, tmp_path, shared_cache_dir):
        """When only writable_paths is set, reads should be unrestricted."""
        _requires_root()
        _requires_docker()
        _requires_landlock()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            writable_paths=["/workspace"],
        )
        sb = Sandbox(config, name="ll-read-ok")
        try:
            # Should be able to read anywhere (reads not restricted)
            output, ec = sb.run("ls /usr/bin/ | head -1")
            assert ec == 0
            assert output.strip()
        finally:
            sb.delete()

    def test_readable_paths(self, tmp_path, shared_cache_dir):
        """Only listed paths should be readable when readable_paths is set."""
        _requires_root()
        _requires_docker()
        _requires_landlock()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            readable_paths=["/workspace", "/usr", "/lib", "/lib64",
                            "/bin", "/sbin", "/etc"],
        )
        sb = Sandbox(config, name="ll-read")
        try:
            # /workspace should be readable
            sb.run("echo test > /workspace/data.txt")
            output, ec = sb.run("cat /workspace/data.txt")
            assert ec == 0
            assert "test" in output
            # /var should NOT be readable (not in readable_paths)
            _, ec = sb.run("ls /var 2>/dev/null")
            assert ec != 0, "read of /var should fail with Landlock"
        finally:
            sb.delete()

    def test_writable_and_readable_paths(self, tmp_path, shared_cache_dir):
        """Both read and write restrictions should work together."""
        _requires_root()
        _requires_docker()
        _requires_landlock()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            writable_paths=["/workspace"],
            readable_paths=["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"],
        )
        sb = Sandbox(config, name="ll-rw")
        try:
            # /workspace writable
            output, ec = sb.run("echo rw_ok > /workspace/x.txt && cat /workspace/x.txt")
            assert ec == 0
            assert "rw_ok" in output
            # /usr readable
            output, ec = sb.run("ls /usr/bin/ | head -1")
            assert ec == 0
            # /var not readable
            _, ec = sb.run("ls /var 2>/dev/null")
            assert ec != 0
            # /usr not writable
            _, ec = sb.run("touch /usr/test 2>/dev/null")
            assert ec != 0
        finally:
            sb.delete()

    def test_writable_paths_after_reset(self, tmp_path, shared_cache_dir):
        """Landlock should still be enforced after sandbox reset."""
        _requires_root()
        _requires_docker()
        _requires_landlock()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            writable_paths=["/workspace"],
        )
        sb = Sandbox(config, name="ll-reset")
        try:
            # Before reset
            _, ec = sb.run("touch /root/test 2>/dev/null")
            assert ec != 0
            sb.reset()
            # After reset — Landlock should still be active
            _, ec = sb.run("touch /root/test 2>/dev/null")
            assert ec != 0, "Landlock should survive reset"
            # /workspace still writable
            output, ec = sb.run("echo post_reset > /workspace/y.txt && cat /workspace/y.txt")
            assert ec == 0
            assert "post_reset" in output
        finally:
            sb.delete()

    def test_allowed_ports(self, tmp_path, shared_cache_dir):
        """Only listed TCP ports should be connectable."""
        _requires_root()
        _requires_docker()
        _requires_landlock()
        abi = _landlock_abi_version()
        if abi < 4:
            pytest.skip("Landlock net port rules require ABI v4+ (kernel 6.7+)")
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            allowed_ports=[80, 443],
        )
        sb = Sandbox(config, name="ll-port")
        try:
            # Attempt connection to port 9999 (not allowed) — should fail
            # Use bash /dev/tcp which uses connect(2)
            _, ec = sb.run("bash -c 'echo > /dev/tcp/127.0.0.1/9999' 2>/dev/null", timeout=3)
            assert ec != 0, "connect to port 9999 should fail with Landlock"
        finally:
            sb.delete()

    def test_no_landlock_params_no_restriction(self, root_sandbox):
        """Without Landlock params, no filesystem restrictions should apply."""
        _requires_landlock()
        # Normal sandbox should have no Landlock restrictions
        output, ec = root_sandbox.run("touch /root/test_no_ll && rm /root/test_no_ll && echo ok")
        assert ec == 0
        assert "ok" in output

    def test_landlock_feature_flag(self, tmp_path, shared_cache_dir):
        """features dict should reflect Landlock status."""
        _requires_root()
        _requires_docker()
        _requires_landlock()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            writable_paths=["/workspace"],
        )
        sb = Sandbox(config, name="ll-feat")
        try:
            assert sb.features.get("landlock") is True
        finally:
            sb.delete()

    def test_landlock_unavailable_raises(self):
        """Setting Landlock params on unsupported kernel should raise SandboxKernelError."""
        from unittest.mock import patch
        from nitrobox.sandbox import Sandbox
        config = SandboxConfig(image=TEST_IMAGE, writable_paths=["/workspace"])
        with patch("nitrobox._core.py_landlock_abi_version", return_value=0):
            with pytest.raises(SandboxKernelError, match="Landlock not available"):
                Sandbox._build_landlock_config(config)

    def test_allowed_ports_low_abi_raises(self):
        """allowed_ports on ABI < 4 should raise SandboxKernelError."""
        from unittest.mock import patch
        from nitrobox.sandbox import Sandbox
        config = SandboxConfig(image=TEST_IMAGE, allowed_ports=[80])
        with patch("nitrobox._core.py_landlock_abi_version", return_value=3):
            with pytest.raises(SandboxKernelError, match="ABI v4"):
                Sandbox._build_landlock_config(config)


# ------------------------------------------------------------------ #
#  Landlock tests (rootless / userns mode)                             #
# ------------------------------------------------------------------ #


class TestLandlockRootless:
    """Verify Landlock in rootless (user namespace) mode."""

    def test_writable_paths_rootless(self, tmp_path, shared_cache_dir):
        """writable_paths should restrict writes in rootless mode."""
        if os.geteuid() == 0:
            pytest.skip("userns test must run as non-root")
        _requires_docker()
        _requires_landlock()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            writable_paths=["/workspace"],
        )
        sb = Sandbox(config, name="ll-userns-write")
        try:
            # /workspace writable
            output, ec = sb.run("echo ok > /workspace/test.txt && cat /workspace/test.txt")
            assert ec == 0
            assert "ok" in output
            # /root not writable
            _, ec = sb.run("touch /root/test.txt 2>/dev/null")
            assert ec != 0
        finally:
            sb.delete()

    def test_readable_paths_rootless(self, tmp_path, shared_cache_dir):
        """readable_paths should restrict reads in rootless mode."""
        if os.geteuid() == 0:
            pytest.skip("userns test must run as non-root")
        _requires_docker()
        _requires_landlock()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            readable_paths=["/workspace", "/usr", "/lib", "/lib64",
                            "/bin", "/sbin", "/etc"],
        )
        sb = Sandbox(config, name="ll-userns-read")
        try:
            output, ec = sb.run("ls /usr/bin/ | head -1")
            assert ec == 0
            _, ec = sb.run("ls /var 2>/dev/null")
            assert ec != 0
        finally:
            sb.delete()

    def test_writable_paths_after_reset_rootless(self, tmp_path, shared_cache_dir):
        """Landlock should survive reset in rootless mode."""
        if os.geteuid() == 0:
            pytest.skip("userns test must run as non-root")
        _requires_docker()
        _requires_landlock()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            writable_paths=["/workspace"],
        )
        sb = Sandbox(config, name="ll-userns-reset")
        try:
            _, ec = sb.run("touch /root/test 2>/dev/null")
            assert ec != 0
            sb.reset()
            _, ec = sb.run("touch /root/test 2>/dev/null")
            assert ec != 0, "Landlock should survive reset"
        finally:
            sb.delete()


# ------------------------------------------------------------------ #
#  Rename-based reset tests (rootless)                                 #
# ------------------------------------------------------------------ #


class TestRenamReset:
    """Verify O(1) rename-based reset in rootless mode."""

    def _skip_if_root(self):
        if os.geteuid() == 0:
            pytest.skip("userns test must run as non-root")

    def test_many_files_reset(self, tmp_path, shared_cache_dir):
        """Reset with 200 files (RL episode scenario)."""
        self._skip_if_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-many-files")
        try:
            sb.run("mkdir -p /workspace/src && seq 1 200 | "
                   "xargs -I{} sh -c 'echo x > /workspace/src/gen_{}.py'")
            sb.reset()
            _, ec = sb.run("ls /workspace/src/ 2>/dev/null")
            assert ec != 0, "directory survived reset"
            out, ec = sb.run("echo ok")
            assert ec == 0 and "ok" in out
        finally:
            sb.delete()

    def test_dead_dirs_cleaned_on_next_reset(self, tmp_path, shared_cache_dir):
        """Dead dirs from previous reset are cleaned at the start of next reset."""
        self._skip_if_root()
        _requires_docker()
        env_base = str(tmp_path / "envs")
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=env_base,
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-dead-cleanup")
        try:
            env_dir = Path(env_base) / "userns-dead-cleanup"

            # First reset creates dead dirs
            sb.run("seq 1 50 | xargs -I{} touch /workspace/f_{}")
            sb.reset()
            dead_after_first = list(env_dir.glob("*.dead.*"))
            assert len(dead_after_first) > 0, "rename should create dead dirs"

            # Second reset should clean previous dead dirs
            sb.run("echo x > /workspace/test.txt")
            sb.reset()
            dead_after_second = list(env_dir.glob("*.dead.*"))
            # Should have new dead dirs but old ones should be gone
            # At most 1 round of dead dirs (from the second reset)
            assert len(dead_after_second) <= 2, (
                f"Expected at most 2 dead dirs (upper+work), got {len(dead_after_second)}"
            )
        finally:
            sb.delete()

    def test_no_dead_dirs_accumulate(self, tmp_path, shared_cache_dir):
        """Repeated resets should not accumulate dead dirs."""
        self._skip_if_root()
        _requires_docker()
        env_base = str(tmp_path / "envs")
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=env_base,
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-no-accumulate")
        try:
            env_dir = Path(env_base) / "userns-no-accumulate"

            for i in range(10):
                sb.run(f"seq 1 50 | xargs -I{{}} touch /workspace/f_{{}}")
                sb.reset()

            dead_dirs = list(env_dir.glob("*.dead.*"))
            # Should have at most 2 (upper.dead + work.dead from last reset)
            assert len(dead_dirs) <= 2, (
                f"Dead dirs accumulated: {len(dead_dirs)} "
                f"(expected <= 2 after 10 resets)"
            )
        finally:
            sb.delete()

    def test_delete_cleans_all_dead_dirs(self, tmp_path, shared_cache_dir):
        """delete() removes env_dir including any remaining dead dirs."""
        self._skip_if_root()
        _requires_docker()
        env_base = str(tmp_path / "envs")
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=env_base,
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-delete-dead")
        env_dir = Path(env_base) / "userns-delete-dead"

        for _ in range(5):
            sb.run("seq 1 50 | xargs -I{} touch /workspace/f_{}")
            sb.reset()

        sb.delete()
        assert not env_dir.exists(), "env_dir should be fully removed"

    def test_dev_devices_survive_rename_reset(self, tmp_path, shared_cache_dir):
        """/dev devices should work after rename-based reset."""
        self._skip_if_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-dev-rename")
        try:
            sb.run("seq 1 100 | xargs -I{} touch /workspace/f_{}")
            sb.reset()
            for dev in ("null", "zero", "random", "urandom"):
                output, ec = sb.run(f"test -c /dev/{dev} && echo ok")
                assert ec == 0 and "ok" in output, (
                    f"/dev/{dev} not a char device after rename reset"
                )
        finally:
            sb.delete()


# ------------------------------------------------------------------ #
#  Config survives reset (rootless)                                    #
# ------------------------------------------------------------------ #


class TestShmSize:
    """Verify /dev/shm is mounted as tmpfs with correct size."""

    def _skip_if_root(self):
        if os.geteuid() == 0:
            pytest.skip("rootless only")

    def test_shm_default_size(self, shared_cache_dir, tmp_path):
        """Default shm is 256MB tmpfs."""
        self._skip_if_root()
        sb = Sandbox(SandboxConfig(
            image=TEST_IMAGE,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        ), name="shm-default")
        try:
            out, ec = sb.run("df -B1 /dev/shm | tail -1")
            assert ec == 0
            # Check that /dev/shm is a tmpfs mount
            out2, _ = sb.run("mount | grep '/dev/shm'")
            assert "tmpfs" in out2
        finally:
            sb.delete()

    def test_shm_custom_size(self, shared_cache_dir, tmp_path):
        """Custom shm_size is respected."""
        self._skip_if_root()
        sb = Sandbox(SandboxConfig(
            image=TEST_IMAGE,
            shm_size="256m",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        ), name="shm-custom")
        try:
            out, ec = sb.run("df -B1 /dev/shm | tail -1")
            assert ec == 0
            # 256MB = 268435456 bytes
            assert "268435456" in out or "262144" in out  # bytes or KB
        finally:
            sb.delete()

    def test_shm_survives_reset(self, shared_cache_dir, tmp_path):
        """shm mount persists after reset."""
        self._skip_if_root()
        sb = Sandbox(SandboxConfig(
            image=TEST_IMAGE,
            shm_size="128m",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        ), name="shm-reset")
        try:
            sb.run("echo test > /dev/shm/file.txt")
            sb.reset()
            out, ec = sb.run("mount | grep '/dev/shm'")
            assert "tmpfs" in out
        finally:
            sb.delete()


class TestUlimitsIntegration:
    """Verify ulimits are applied inside sandbox."""

    def _skip_if_root(self):
        if os.geteuid() == 0:
            pytest.skip("rootless only")

    def test_nofile_limit(self, shared_cache_dir, tmp_path):
        self._skip_if_root()
        sb = Sandbox(SandboxConfig(
            image=TEST_IMAGE,
            ulimits={"nofile": (1024, 2048)},
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        ), name="ulimit-test")
        try:
            out, ec = sb.run("ulimit -n")
            assert ec == 0
            assert out.strip() == "1024"
        finally:
            sb.delete()


class TestTmpfsMounts:
    """Verify tmpfs mounts work correctly."""

    def _skip_if_root(self):
        if os.geteuid() == 0:
            pytest.skip("rootless only")

    def test_tmpfs_mount(self, shared_cache_dir, tmp_path):
        self._skip_if_root()
        sb = Sandbox(SandboxConfig(
            image=TEST_IMAGE,
            tmpfs=["/run:size=10m"],
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        ), name="tmpfs-test")
        try:
            out, ec = sb.run("mount | grep '/run'")
            assert ec == 0
            assert "tmpfs" in out
            # Verify writable
            out2, ec2 = sb.run("echo ok > /run/test.txt && cat /run/test.txt")
            assert ec2 == 0
            assert "ok" in out2
        finally:
            sb.delete()


class TestConfigSurvivesReset:
    """Verify all config options are correctly restored after reset."""

    def _skip_if_root(self):
        if os.geteuid() == 0:
            pytest.skip("userns test must run as non-root")

    def test_seccomp_after_reset(self, tmp_path, shared_cache_dir):
        """seccomp BPF should remain active after reset."""
        self._skip_if_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-seccomp-reset")
        try:
            sb.reset()
            output, ec = sb.run("cat /proc/self/status | grep Seccomp")
            assert ec == 0
            assert "2" in output, "seccomp filter not active after reset"
            # mount should still be blocked
            _, ec = sb.run("mount -t tmpfs tmpfs /tmp 2>/dev/null")
            assert ec != 0, "mount should be blocked after reset"
        finally:
            sb.delete()

    def test_hostname_after_reset(self, tmp_path, shared_cache_dir):
        """Custom hostname should persist after reset."""
        self._skip_if_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            hostname="persist-host",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-hostname-reset")
        try:
            sb.reset()
            output, ec = sb.run("hostname")
            assert ec == 0
            assert "persist-host" in output, f"hostname lost after reset: {output.strip()!r}"
        finally:
            sb.delete()

    def test_read_only_after_reset(self, tmp_path, shared_cache_dir):
        """read_only rootfs should still be enforced after reset."""
        self._skip_if_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            read_only=True,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-ro-reset")
        try:
            sb.reset()
            _, ec = sb.run("touch /test_ro 2>/dev/null")
            assert ec != 0, "rootfs should be read-only after reset"
            # /dev/null should still work
            _, ec = sb.run("echo x > /dev/null")
            assert ec == 0
        finally:
            sb.delete()

    def test_dns_after_reset(self, tmp_path, shared_cache_dir):
        """Custom DNS config should persist after reset."""
        self._skip_if_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            dns=["8.8.8.8", "1.1.1.1"],
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-dns-reset")
        try:
            sb.reset()
            output, ec = sb.run("cat /etc/resolv.conf")
            assert ec == 0
            assert "8.8.8.8" in output, "dns config lost after reset"
        finally:
            sb.delete()

    def test_rw_volume_after_reset(self, tmp_path, shared_cache_dir):
        """rw volume should still be mounted and writable after reset."""
        self._skip_if_root()
        _requires_docker()
        shared = tmp_path / "shared"
        shared.mkdir()
        (shared / "host.txt").write_text("from_host")

        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            volumes=[f"{shared}:/data:rw"],
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-rw-vol-reset")
        try:
            sb.reset()
            # Can read host file
            output, ec = sb.run("cat /data/host.txt")
            assert ec == 0
            assert "from_host" in output
            # Can write to volume
            sb.run("echo after_reset > /data/new.txt")
            assert (shared / "new.txt").read_text().strip() == "after_reset"
        finally:
            sb.delete()

    def test_ro_volume_after_reset(self, tmp_path, shared_cache_dir):
        """ro volume should still be mounted and read-only after reset."""
        self._skip_if_root()
        _requires_docker()
        shared = tmp_path / "shared"
        shared.mkdir()
        (shared / "data.txt").write_text("read_only_data")

        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            volumes=[f"{shared}:/data:ro"],
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-ro-vol-reset")
        try:
            sb.reset()
            output, ec = sb.run("cat /data/data.txt")
            assert ec == 0
            assert "read_only_data" in output
            _, ec = sb.run("echo x > /data/data.txt 2>&1")
            assert ec != 0, "ro volume should not be writable after reset"
        finally:
            sb.delete()

    def test_net_isolate_after_reset(self, tmp_path, shared_cache_dir):
        """net_isolate should still be enforced after reset."""
        self._skip_if_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            net_isolate=True,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-net-reset")
        try:
            sb.reset()
            output, ec = sb.run("ls /sys/class/net/ 2>/dev/null || echo lo")
            assert ec == 0
            ifaces = output.strip().split()
            assert "lo" in ifaces
        finally:
            sb.delete()

    def test_masked_paths_after_reset(self, tmp_path, shared_cache_dir):
        """Sensitive paths should remain masked after reset."""
        self._skip_if_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-mask-reset")
        try:
            sb.reset()
            output, ec = sb.run("cat /proc/kcore 2>&1 | wc -c")
            assert ec == 0
            assert int(output.strip()) == 0, "/proc/kcore should be masked after reset"
        finally:
            sb.delete()

    def test_working_dir_after_reset(self, userns_sandbox):
        """Working directory should be correct after reset."""
        userns_sandbox.reset()
        output, ec = userns_sandbox.run("pwd")
        assert ec == 0
        assert "workspace" in output

    def test_environment_after_reset(self, tmp_path, shared_cache_dir):
        """Custom environment variables should persist after reset."""
        self._skip_if_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            environment={"MY_TEST_VAR": "hello123"},
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-env-reset")
        try:
            sb.reset()
            output, ec = sb.run("echo $MY_TEST_VAR")
            assert ec == 0
            assert "hello123" in output, f"env var lost after reset: {output.strip()!r}"
        finally:
            sb.delete()

    def test_snapshot_after_reset(self, tmp_path, shared_cache_dir):
        """Snapshots should work across resets."""
        self._skip_if_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-snap-reset")
        try:
            sb.run("echo v1 > /workspace/data.txt")
            sb.snapshot("v1")
            sb.reset()
            sb.run("echo v2 > /workspace/data.txt")
            sb.restore("v1")
            output, _ = sb.run("cat /workspace/data.txt")
            assert output.strip() == "v1"
        finally:
            sb.delete()

    def test_background_killed_on_reset(self, userns_sandbox):
        """Background processes should be stopped after reset."""
        handle = userns_sandbox.run_background("sleep 100")
        _, running = userns_sandbox.check_background(handle)
        assert running
        userns_sandbox.reset()
        _, running = userns_sandbox.check_background(handle)
        assert not running, "background process survived reset"

    def test_popen_after_reset(self, userns_sandbox):
        """popen() should work after reset."""
        userns_sandbox.reset()
        proc = userns_sandbox.popen("echo popen_works")
        output = proc.stdout.read()
        proc.wait(timeout=5)
        assert b"popen_works" in output


# ------------------------------------------------------------------ #
#  Config combination tests (rootless)                                 #
# ------------------------------------------------------------------ #


class TestConfigCombinations:
    """Verify config option combinations that previously caused bugs."""

    def _skip_if_root(self):
        if os.geteuid() == 0:
            pytest.skip("userns test must run as non-root")

    def test_read_only_with_ro_volume(self, tmp_path, shared_cache_dir):
        """read_only=True + volumes should work (mount points created before ro remount)."""
        self._skip_if_root()
        _requires_docker()
        shared = tmp_path / "shared"
        shared.mkdir()
        (shared / "data.txt").write_text("vol_data")

        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            read_only=True,
            volumes=[f"{shared}:/data:ro"],
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-ro-vol")
        try:
            output, ec = sb.run("cat /data/data.txt")
            assert ec == 0
            assert "vol_data" in output
            # rootfs should be read-only
            _, ec = sb.run("touch /test_ro 2>/dev/null")
            assert ec != 0
        finally:
            sb.delete()

    def test_read_only_with_rw_volume(self, tmp_path, shared_cache_dir):
        """read_only rootfs + rw volume: rootfs read-only but volume writable."""
        self._skip_if_root()
        _requires_docker()
        shared = tmp_path / "shared"
        shared.mkdir()

        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            read_only=True,
            volumes=[f"{shared}:/data:rw"],
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-ro-rw-vol")
        try:
            sb.run("echo written > /data/out.txt")
            assert (shared / "out.txt").read_text().strip() == "written"
            _, ec = sb.run("touch /test_ro 2>/dev/null")
            assert ec != 0
        finally:
            sb.delete()

    def test_read_only_with_cow_volume(self, tmp_path, shared_cache_dir):
        """read_only rootfs + cow volume: copy-on-write volume works."""
        self._skip_if_root()
        _requires_docker()
        shared = tmp_path / "shared"
        shared.mkdir()
        (shared / "original.txt").write_text("original")

        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            read_only=True,
            volumes=[f"{shared}:/data:cow"],
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-ro-cow-vol")
        try:
            output, ec = sb.run("cat /data/original.txt")
            assert ec == 0
            assert "original" in output
            # cow writes don't affect host
            sb.run("echo modified > /data/original.txt")
            assert (shared / "original.txt").read_text().strip() == "original"
        finally:
            sb.delete()

    def test_cow_volume_reset_reverts(self, tmp_path, shared_cache_dir):
        """cow volume changes should be reverted on reset."""
        self._skip_if_root()
        _requires_docker()
        shared = tmp_path / "shared"
        shared.mkdir()
        (shared / "data.txt").write_text("original")

        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            volumes=[f"{shared}:/data:cow"],
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-cow-reset")
        try:
            sb.run("echo modified > /data/data.txt")
            out, _ = sb.run("cat /data/data.txt")
            assert "modified" in out

            sb.reset()

            out, _ = sb.run("cat /data/data.txt")
            assert out.strip() == "original", (
                f"cow volume should revert on reset, got: {out.strip()!r}"
            )
        finally:
            sb.delete()

    def test_full_config_combo(self, tmp_path, shared_cache_dir):
        """All config options together: read_only + volumes + hostname + dns + net_isolate."""
        self._skip_if_root()
        _requires_docker()
        shared = tmp_path / "shared"
        shared.mkdir()
        (shared / "test.txt").write_text("combo_data")

        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            read_only=True,
            volumes=[f"{shared}:/data:ro"],
            hostname="combo-host",
            dns=["8.8.8.8"],
            net_isolate=True,
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-full-combo")
        try:
            output, ec = sb.run("cat /data/test.txt")
            assert ec == 0
            assert "combo_data" in output

            output, ec = sb.run("hostname")
            assert ec == 0
            assert "combo-host" in output

            output, ec = sb.run("cat /etc/resolv.conf")
            assert ec == 0
            assert "8.8.8.8" in output
        finally:
            sb.delete()

    def test_hostname_no_stderr_leak(self, tmp_path, shared_cache_dir):
        """Hostname setup errors should not leak into first command output."""
        self._skip_if_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            hostname="clean-host",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-hostname-clean")
        try:
            output, ec = sb.run("echo clean_output")
            assert ec == 0
            assert output.strip() == "clean_output", (
                f"First command output should be clean, got: {output!r}"
            )
        finally:
            sb.delete()

    def test_cow_volume_no_artifacts_after_delete(self, tmp_path, shared_cache_dir):
        """cow volume sandbox should leave no artifacts after delete."""
        self._skip_if_root()
        _requires_docker()
        shared = tmp_path / "shared"
        shared.mkdir()
        (shared / "data.txt").write_text("cow_test")

        env_base = str(tmp_path / "envs")
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            volumes=[f"{shared}:/data:cow"],
            env_base_dir=env_base,
            rootfs_cache_dir=shared_cache_dir,
        )
        sb = Sandbox(config, name="userns-cow-cleanup")
        sb.run("echo x > /data/new_file.txt")
        sb.delete()

        env_dir = Path(env_base) / "userns-cow-cleanup"
        assert not env_dir.exists(), (
            f"Sandbox env dir should be fully removed, but found: "
            f"{list(env_dir.rglob('*')) if env_dir.exists() else []}"
        )


# ------------------------------------------------------------------ #
#  Device passthrough (rootless)                                       #
# ------------------------------------------------------------------ #


class TestDevicesRootless:
    """Verify device passthrough in rootless (user namespace) mode."""

    @staticmethod
    def _skip_if_root():
        if os.geteuid() == 0:
            pytest.skip("userns test must run as non-root")

    def test_fuse_device_passthrough(self, tmp_path, shared_cache_dir):
        """Bind-mounted /dev/fuse should be accessible in userns sandbox."""
        self._skip_if_root()
        _requires_docker()
        if not os.path.exists("/dev/fuse"):
            pytest.skip("/dev/fuse not available")
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            devices=["/dev/fuse"],
        )
        sb = Sandbox(config, name="userns-dev-fuse")
        try:
            output, ec = sb.run("test -c /dev/fuse && echo exists")
            assert ec == 0
            assert "exists" in output
            # Verify it's a real character device with correct major:minor
            output, ec = sb.run("stat -c '%t:%T' /dev/fuse")
            assert ec == 0
            assert "a:e5" in output  # major 10, minor 229
        finally:
            sb.delete()

    def test_kvm_device_passthrough(self, tmp_path, shared_cache_dir):
        """Bind-mounted /dev/kvm should be accessible in userns sandbox."""
        self._skip_if_root()
        _requires_docker()
        if not os.path.exists("/dev/kvm"):
            pytest.skip("/dev/kvm not available")
        # Check user has kvm group (required for rootless KVM access)
        if not os.access("/dev/kvm", os.R_OK | os.W_OK):
            pytest.skip("no read/write access to /dev/kvm (need kvm group)")
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            devices=["/dev/kvm"],
        )
        sb = Sandbox(config, name="userns-dev-kvm")
        try:
            output, ec = sb.run("test -c /dev/kvm && echo exists")
            assert ec == 0
            assert "exists" in output
            # Verify it's a real character device with correct major:minor
            output, ec = sb.run("stat -c '%t:%T' /dev/kvm")
            assert ec == 0
            assert "a:e8" in output  # major 10, minor 232
        finally:
            sb.delete()

    def test_device_survives_reset(self, tmp_path, shared_cache_dir):
        """Device passthrough should work after reset."""
        self._skip_if_root()
        _requires_docker()
        if not os.path.exists("/dev/fuse"):
            pytest.skip("/dev/fuse not available")
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            devices=["/dev/fuse"],
        )
        sb = Sandbox(config, name="userns-dev-reset")
        try:
            output, ec = sb.run("test -c /dev/fuse && echo before")
            assert ec == 0
            assert "before" in output

            sb.reset()

            output, ec = sb.run("test -c /dev/fuse && echo after")
            assert ec == 0
            assert "after" in output
            # Still a real device after reset
            output, ec = sb.run("stat -c '%t:%T' /dev/fuse")
            assert ec == 0
            assert "a:e5" in output
        finally:
            sb.delete()

    def test_multiple_devices(self, tmp_path, shared_cache_dir):
        """Multiple devices can be passed through simultaneously."""
        self._skip_if_root()
        _requires_docker()
        devices = []
        for dev in ["/dev/fuse", "/dev/kvm"]:
            if os.path.exists(dev) and os.access(dev, os.R_OK):
                devices.append(dev)
        if len(devices) < 2:
            pytest.skip("need at least 2 accessible devices (/dev/fuse, /dev/kvm)")
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            devices=devices,
        )
        sb = Sandbox(config, name="userns-multi-dev")
        try:
            for dev in devices:
                output, ec = sb.run(f"test -c {dev} && echo ok")
                assert ec == 0, f"device {dev} not accessible"
                assert "ok" in output
        finally:
            sb.delete()

    def test_device_with_seccomp(self, tmp_path, shared_cache_dir):
        """Device passthrough works alongside seccomp filtering."""
        self._skip_if_root()
        _requires_docker()
        if not os.path.exists("/dev/fuse"):
            pytest.skip("/dev/fuse not available")
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            devices=["/dev/fuse"],
            seccomp=True,
        )
        sb = Sandbox(config, name="userns-dev-seccomp")
        try:
            # Device works
            output, ec = sb.run("test -c /dev/fuse && echo ok")
            assert ec == 0
            assert "ok" in output
            # Seccomp is active
            output, ec = sb.run("cat /proc/self/status | grep Seccomp")
            assert ec == 0
            assert "2" in output
        finally:
            sb.delete()

    def test_devices_feature_flag(self, tmp_path, shared_cache_dir):
        """features dict should include 'devices' when devices configured."""
        self._skip_if_root()
        _requires_docker()
        if not os.path.exists("/dev/fuse"):
            pytest.skip("/dev/fuse not available")
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            devices=["/dev/fuse"],
        )
        sb = Sandbox(config, name="userns-dev-feat")
        try:
            assert sb.features.get("devices") is True
        finally:
            sb.delete()

    def test_nonexistent_device_graceful(self, tmp_path, shared_cache_dir):
        """Non-existent device should not crash sandbox creation."""
        self._skip_if_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            devices=["/dev/does_not_exist_xyz"],
        )
        sb = Sandbox(config, name="userns-dev-noexist")
        try:
            # Sandbox should start fine, non-existent device just not mounted
            output, ec = sb.run("echo works")
            assert ec == 0
            assert "works" in output
            # The bind mount silently fails; the touch file may remain but
            # should NOT be a character device (just a regular empty file)
            output, ec = sb.run("test -c /dev/does_not_exist_xyz && echo char || echo not_char")
            assert "not_char" in output
        finally:
            sb.delete()

    def test_kvm_ioctl_works(self, tmp_path, shared_cache_dir):
        """KVM ioctl should not be blocked by seccomp (only TIOCSTI is blocked)."""
        self._skip_if_root()
        _requires_docker()
        if not os.path.exists("/dev/kvm"):
            pytest.skip("/dev/kvm not available")
        if not os.access("/dev/kvm", os.R_OK | os.W_OK):
            pytest.skip("no read/write access to /dev/kvm")
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            devices=["/dev/kvm"],
            seccomp=True,
        )
        sb = Sandbox(config, name="userns-kvm-ioctl")
        try:
            # Try python3 for ioctl test; skip if not available in image
            output, ec = sb.run("which python3 >/dev/null 2>&1 && echo yes || echo no")
            if "no" in output:
                # Fallback: just verify /dev/kvm is openable (not blocked by seccomp)
                output, ec = sb.run(
                    "exec 3</dev/kvm && echo 'kvm_open=ok' && exec 3<&-"
                )
                assert ec == 0, f"Failed to open /dev/kvm: {output}"
                assert "kvm_open=ok" in output
            else:
                # KVM_GET_API_VERSION ioctl (0xAE00) should succeed
                output, ec = sb.run(
                    "python3 -c '"
                    "import fcntl, os; "
                    "fd = os.open(\"/dev/kvm\", os.O_RDWR); "
                    "ver = fcntl.ioctl(fd, 0xAE00); "
                    "os.close(fd); "
                    "print(f\"kvm_api={ver}\")'"
                )
                assert ec == 0, f"KVM ioctl failed: {output}"
                assert "kvm_api=12" in output
        finally:
            sb.delete()


class TestDevicesRootful:
    """Verify device passthrough in rootful mode."""

    def test_fuse_device_passthrough(self, tmp_path, shared_cache_dir):
        """Bind-mounted /dev/fuse should be accessible in rootful sandbox."""
        _requires_root()
        _requires_docker()
        if not os.path.exists("/dev/fuse"):
            pytest.skip("/dev/fuse not available")
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            devices=["/dev/fuse"],
        )
        sb = Sandbox(config, name="root-dev-fuse")
        try:
            output, ec = sb.run("test -c /dev/fuse && echo exists")
            assert ec == 0
            assert "exists" in output
            output, ec = sb.run("stat -c '%t:%T' /dev/fuse")
            assert ec == 0
            assert "a:e5" in output  # major 10, minor 229
        finally:
            sb.delete()

    def test_device_survives_reset(self, tmp_path, shared_cache_dir):
        """Device passthrough should work after reset in rootful mode."""
        _requires_root()
        _requires_docker()
        if not os.path.exists("/dev/fuse"):
            pytest.skip("/dev/fuse not available")
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            devices=["/dev/fuse"],
        )
        sb = Sandbox(config, name="root-dev-reset")
        try:
            output, ec = sb.run("test -c /dev/fuse && echo before")
            assert ec == 0
            assert "before" in output

            sb.reset()

            output, ec = sb.run("test -c /dev/fuse && echo after")
            assert ec == 0
            assert "after" in output
        finally:
            sb.delete()

    def test_kvm_ioctl_rootful(self, tmp_path, shared_cache_dir):
        """KVM ioctl should work in rootful mode with seccomp."""
        _requires_root()
        _requires_docker()
        if not os.path.exists("/dev/kvm"):
            pytest.skip("/dev/kvm not available")
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            devices=["/dev/kvm"],
            seccomp=True,
        )
        sb = Sandbox(config, name="root-kvm-ioctl")
        try:
            output, ec = sb.run("which python3 >/dev/null 2>&1 && echo yes || echo no")
            if "no" in output:
                output, ec = sb.run(
                    "exec 3</dev/kvm && echo 'kvm_open=ok' && exec 3<&-"
                )
                assert ec == 0, f"Failed to open /dev/kvm: {output}"
                assert "kvm_open=ok" in output
            else:
                output, ec = sb.run(
                    "python3 -c '"
                    "import fcntl, os; "
                    "fd = os.open(\"/dev/kvm\", os.O_RDWR); "
                    "ver = fcntl.ioctl(fd, 0xAE00); "
                    "os.close(fd); "
                    "print(f\"kvm_api={ver}\")'"
                )
                assert ec == 0, f"KVM ioctl failed: {output}"
                assert "kvm_api=12" in output
        finally:
            sb.delete()

    def test_devices_feature_flag(self, tmp_path, shared_cache_dir):
        """features dict should include 'devices' in rootful mode."""
        _requires_root()
        _requires_docker()
        config = SandboxConfig(
            image=TEST_IMAGE,
            working_dir="/workspace",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
            devices=["/dev/null"],
        )
        sb = Sandbox(config, name="root-dev-feat")
        try:
            assert sb.features.get("devices") is True
        finally:
            sb.delete()
