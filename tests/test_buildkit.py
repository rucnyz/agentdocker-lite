"""Tests for the BuildKit backend integration."""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest


def _requires_buildkitd():
    """Skip if buildkitd is not available."""
    from nitrobox.image.buildkit import BuildKitManager
    bk = BuildKitManager.get()
    if not bk.available:
        pytest.skip("buildkitd not found")


def _requires_gobin():
    """Skip if nitrobox-core Go binary is not available."""
    from nitrobox._gobin import gobin
    bin_path = gobin()
    if not (os.path.isfile(bin_path) and os.access(bin_path, os.X_OK)):
        pytest.skip("requires nitrobox-core Go binary")


def _requires_rootlesskit():
    """Skip if rootlesskit is not available."""
    if shutil.which("rootlesskit") is None:
        # Also check GOPATH/bin
        gopath = subprocess.run(
            ["go", "env", "GOPATH"], capture_output=True, text=True
        ).stdout.strip()
        if not os.path.isfile(os.path.join(gopath, "bin", "rootlesskit")):
            pytest.skip("rootlesskit not found")


class TestBuildKitManager:
    """Tests for BuildKitManager singleton."""

    def test_singleton(self):
        from nitrobox.image.buildkit import BuildKitManager
        a = BuildKitManager.get()
        b = BuildKitManager.get()
        assert a is b

    def test_available_property(self):
        from nitrobox.image.buildkit import BuildKitManager
        bk = BuildKitManager.get()
        # Should return bool without raising
        assert isinstance(bk.available, bool)


class TestBuildKitDaemon:
    """Tests for buildkitd lifecycle management."""

    def test_start_idempotent(self):
        _requires_buildkitd()
        _requires_gobin()
        _requires_rootlesskit()

        from nitrobox.image.buildkit import BuildKitManager
        bk = BuildKitManager.get()

        # Start
        socket = bk.ensure_running()
        assert socket
        assert os.path.exists(socket)

        # Already running — should be idempotent
        socket2 = bk.ensure_running()
        assert socket2 == socket


class TestBuildKitBuild:
    """Tests for BuildKit image builds."""

    @pytest.fixture
    def simple_dockerfile(self, tmp_path):
        """Create a minimal Dockerfile for testing."""
        df = tmp_path / "Dockerfile"
        df.write_text("FROM alpine:latest\nRUN echo hello > /hello.txt\n")
        return tmp_path

    def test_build_simple(self, simple_dockerfile):
        _requires_buildkitd()
        _requires_gobin()
        _requires_rootlesskit()

        from nitrobox.image.buildkit import BuildKitManager
        bk = BuildKitManager.get()

        result = bk.build(
            str(simple_dockerfile), "Dockerfile", "test-bk-simple"
        )
        assert "manifest_digest" in result
        assert result["manifest_digest"].startswith("sha256:")
        assert "layer_paths" in result
        assert len(result["layer_paths"]) > 0
        # Verify layer paths exist
        for p in result["layer_paths"]:
            assert os.path.isdir(p), f"Layer path does not exist: {p}"

    def test_build_cache_hit(self, simple_dockerfile):
        """Second build of same Dockerfile should be fast (cache hit)."""
        _requires_buildkitd()
        _requires_gobin()
        _requires_rootlesskit()

        import time
        from nitrobox.image.buildkit import BuildKitManager
        bk = BuildKitManager.get()

        # First build (may be cold)
        bk.build(str(simple_dockerfile), "Dockerfile", "test-bk-cache-1")

        # Second build (should be cache hit)
        t0 = time.monotonic()
        result = bk.build(
            str(simple_dockerfile), "Dockerfile", "test-bk-cache-2"
        )
        elapsed = time.monotonic() - t0

        assert result["manifest_digest"].startswith("sha256:")
        # Cache hit should be < 3s (vs ~40s for cold)
        assert elapsed < 5.0, f"Cache hit build took {elapsed:.1f}s, expected < 5s"

    def test_concurrent_builds(self, simple_dockerfile):
        """Multiple concurrent builds should all succeed."""
        _requires_buildkitd()
        _requires_gobin()
        _requires_rootlesskit()

        from concurrent.futures import ThreadPoolExecutor, as_completed
        from nitrobox.image.buildkit import BuildKitManager
        bk = BuildKitManager.get()

        # Warm the cache
        bk.build(str(simple_dockerfile), "Dockerfile", "test-bk-warm")

        # 8 concurrent builds
        def do_build(i):
            return bk.build(
                str(simple_dockerfile), "Dockerfile", f"test-bk-concurrent-{i}"
            )

        results = []
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(do_build, i) for i in range(8)]
            for f in as_completed(futures):
                results.append(f.result())

        assert len(results) == 8
        for r in results:
            assert r["manifest_digest"].startswith("sha256:")
            assert len(r["layer_paths"]) > 0


class TestBuildKitLayerCache:
    """Tests for BuildKit layer cache integration."""

    def test_layer_cache_populated_after_build(self, tmp_path):
        _requires_buildkitd()
        _requires_gobin()
        _requires_rootlesskit()

        from nitrobox.image.buildkit import BuildKitManager, get_buildkit_layers
        bk = BuildKitManager.get()

        df = tmp_path / "Dockerfile"
        df.write_text("FROM alpine:latest\nRUN echo test\n")

        tag = "test-bk-layer-cache"
        bk.build(str(tmp_path), "Dockerfile", tag)

        layers = get_buildkit_layers(tag)
        assert layers is not None
        assert len(layers) > 0

    def test_config_cache_populated_after_build(self, tmp_path):
        _requires_buildkitd()
        _requires_gobin()
        _requires_rootlesskit()

        from nitrobox.image.buildkit import BuildKitManager, get_buildkit_config
        bk = BuildKitManager.get()

        df = tmp_path / "Dockerfile"
        df.write_text("FROM alpine:latest\nWORKDIR /app\nENV FOO=bar\n")

        tag = "test-bk-config-cache"
        bk.build(str(tmp_path), "Dockerfile", tag)

        cfg = get_buildkit_config(tag)
        assert cfg is not None
        config = cfg.get("config", {})
        assert config.get("WorkingDir") == "/app"
        env = config.get("Env", [])
        assert any("FOO=bar" in e for e in env)


class TestBuildKitCLI:
    """Tests for the nitrobox buildkit-stop CLI command."""

    def test_buildkit_stop_command_exists(self):
        """Verify the buildkit-stop CLI command is registered."""
        _requires_gobin()

        result = subprocess.run(
            ["python", "-m", "nitrobox.cli", "--help"],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0
        assert "buildkit-stop" in result.stdout
