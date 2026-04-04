"""Tests for the Docker Engine REST API client and related changes.

Tests cover:
- docker_api.py: socket discovery, registry auth, DockerClient methods
- Rust py_parse_image_ref: image reference parsing via Rust bindings
- Rust image store: py_image_store_get/put/clear
- Integration: registry-first resolution path in rootfs.py

Run with: sudo python -m pytest tests/test_docker_api.py -v
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import tarfile
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from nitrobox.docker_api import (
    DockerAPIError,
    DockerClient,
    DockerSocketError,
    ImageNotFoundError,
    _find_docker_socket,
    _load_registry_auth,
    _resolve_registry_domain,
)


# ====================================================================== #
#  Skip helpers                                                            #
# ====================================================================== #


def _requires_docker():
    """Skip test if Docker daemon is not available."""
    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        pytest.skip("requires Docker")


def _skip_if_no_registry():
    """Skip test if Docker Hub API is unreachable or rate-limited."""
    from nitrobox._registry import get_image_metadata_from_registry

    try:
        get_image_metadata_from_registry("alpine:3.19")
    except Exception:
        pytest.skip("Docker Hub unreachable or rate-limited")


def _docker_socket_available() -> bool:
    """Return True if a Docker socket can be found."""
    try:
        _find_docker_socket()
        return True
    except DockerSocketError:
        return False


def _has_rust_image_store() -> bool:
    """Return True if py_image_store_get/put/clear are available in _core."""
    try:
        from nitrobox._core import py_image_store_clear  # noqa: F401
        return True
    except ImportError:
        return False


def _has_rust_parse_image_ref() -> bool:
    """Return True if py_parse_image_ref is available in _core."""
    try:
        from nitrobox._core import py_parse_image_ref  # noqa: F401
        return True
    except ImportError:
        return False


def _requires_rust_image_store():
    """Skip test if Rust image store bindings are not compiled."""
    if not _has_rust_image_store():
        pytest.skip("requires Rust py_image_store_* bindings (rebuild with maturin)")


def _requires_rust_parse_image_ref():
    """Skip test if Rust py_parse_image_ref binding is not compiled."""
    if not _has_rust_parse_image_ref():
        pytest.skip("requires Rust py_parse_image_ref binding (rebuild with maturin)")


def _skip_if_pull_rate_limited():
    """Skip test if Docker Hub pull rate limit is hit.

    Attempts a lightweight pull of a tiny image tag.  If the daemon
    returns any error (rate limit, auth, network) the test is skipped
    rather than failed, since the test is exercising the *client*
    logic not registry availability.
    """
    try:
        client = DockerClient()
        if client.image_exists("alpine:3.19"):
            return  # Already local, no pull needed
        # Try pulling — if rate limited this will fail
        client.image_pull("alpine:3.19")
    except (DockerAPIError, DockerSocketError, OSError):
        pytest.skip("Docker pull unavailable (rate-limited or network error)")


# ====================================================================== #
#  _find_docker_socket                                                     #
# ====================================================================== #


class TestFindDockerSocket:
    """Socket discovery logic in _find_docker_socket."""

    def test_finds_socket_via_docker_host_env(self, tmp_path):
        """DOCKER_HOST=unix:///path/to/docker.sock is respected."""
        sock = tmp_path / "docker.sock"
        sock.touch()
        with patch.dict(os.environ, {"DOCKER_HOST": f"unix://{sock}"}):
            result = _find_docker_socket()
        assert result == str(sock)

    def test_docker_host_nonexistent_path_falls_through(self, tmp_path):
        """DOCKER_HOST pointing to a nonexistent socket falls through to candidates."""
        # Set DOCKER_HOST to a nonexistent path; also ensure no real socket exists.
        with patch.dict(
            os.environ,
            {"DOCKER_HOST": "unix:///tmp/.nitrobox_test_nonexistent.sock"},
        ):
            with patch("os.path.exists") as mock_exists:
                # DOCKER_HOST path doesn't exist, no candidate exists
                mock_exists.return_value = False
                with pytest.raises(DockerSocketError):
                    _find_docker_socket()

    def test_finds_var_run_docker_sock(self):
        """Falls back to /var/run/docker.sock when it exists."""
        with patch.dict(os.environ, {}, clear=False):
            # Remove DOCKER_HOST if set
            os.environ.pop("DOCKER_HOST", None)
            with patch("os.path.exists") as mock_exists:
                def side_effect(path):
                    return path == "/var/run/docker.sock"

                mock_exists.side_effect = side_effect
                result = _find_docker_socket()
        assert result == "/var/run/docker.sock"

    def test_finds_xdg_runtime_docker_sock(self):
        """Falls back to $XDG_RUNTIME_DIR/docker.sock."""
        with patch.dict(
            os.environ,
            {"XDG_RUNTIME_DIR": "/run/user/1000"},
            clear=False,
        ):
            os.environ.pop("DOCKER_HOST", None)
            with patch("os.path.exists") as mock_exists:
                def side_effect(path):
                    return path == "/run/user/1000/docker.sock"

                mock_exists.side_effect = side_effect
                result = _find_docker_socket()
        assert result == "/run/user/1000/docker.sock"

    def test_finds_podman_sock(self):
        """Falls back to $XDG_RUNTIME_DIR/podman/podman.sock."""
        with patch.dict(
            os.environ,
            {"XDG_RUNTIME_DIR": "/run/user/1000"},
            clear=False,
        ):
            os.environ.pop("DOCKER_HOST", None)
            with patch("os.path.exists") as mock_exists:
                def side_effect(path):
                    return path == "/run/user/1000/podman/podman.sock"

                mock_exists.side_effect = side_effect
                result = _find_docker_socket()
        assert result == "/run/user/1000/podman/podman.sock"

    def test_raises_when_no_socket_found(self):
        """DockerSocketError raised when no socket candidate exists."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DOCKER_HOST", None)
            with patch("os.path.exists", return_value=False):
                with pytest.raises(DockerSocketError):
                    _find_docker_socket()


# ====================================================================== #
#  _resolve_registry_domain                                                #
# ====================================================================== #


class TestResolveRegistryDomain:
    """Registry domain extraction from image references."""

    @pytest.mark.parametrize(
        "image, expected_domain",
        [
            ("ubuntu", "docker.io"),
            ("ubuntu:22.04", "docker.io"),
            ("alexgshaw/repo:tag", "docker.io"),
            ("ghcr.io/org/repo:v1", "ghcr.io"),
            ("localhost:5000/img:v1", "localhost:5000"),
            ("myregistry.com/repo:latest", "myregistry.com"),
            ("docker.io/library/python:3.13", "docker.io"),
        ],
        ids=[
            "docker_hub_bare_name",
            "docker_hub_with_tag",
            "docker_hub_with_org",
            "ghcr",
            "localhost_with_port",
            "custom_registry",
            "docker_io_explicit",
        ],
    )
    def test_resolve_registry_domain(self, image, expected_domain):
        assert _resolve_registry_domain(image) == expected_domain


# ====================================================================== #
#  _load_registry_auth                                                     #
# ====================================================================== #


class TestLoadRegistryAuth:
    """Registry auth loading from ~/.docker/config.json."""

    def _make_docker_config(self, tmp_home: Path, auths: dict) -> None:
        """Write a fake ~/.docker/config.json."""
        docker_dir = tmp_home / ".docker"
        docker_dir.mkdir(parents=True, exist_ok=True)
        config_path = docker_dir / "config.json"
        config_path.write_text(json.dumps({"auths": auths}))

    def test_docker_hub_auth(self, tmp_path):
        """Loads auth for Docker Hub images via index.docker.io key."""
        creds = base64.b64encode(b"myuser:mypass").decode()
        self._make_docker_config(tmp_path, {
            "https://index.docker.io/v1/": {"auth": creds},
        })
        with patch("pathlib.Path.home", return_value=tmp_path):
            result = _load_registry_auth("ubuntu:22.04")

        # Decode the base64 result to verify it contains the credentials
        decoded = json.loads(base64.b64decode(result))
        assert decoded["username"] == "myuser"
        assert decoded["password"] == "mypass"

    def test_ghcr_auth(self, tmp_path):
        """Loads auth for ghcr.io images."""
        creds = base64.b64encode(b"ghcruser:ghcrtoken").decode()
        self._make_docker_config(tmp_path, {
            "ghcr.io": {"auth": creds},
        })
        with patch("pathlib.Path.home", return_value=tmp_path):
            result = _load_registry_auth("ghcr.io/org/repo:v1")

        decoded = json.loads(base64.b64decode(result))
        assert decoded["username"] == "ghcruser"
        assert decoded["password"] == "ghcrtoken"

    def test_no_config_returns_empty_auth(self, tmp_path):
        """Returns empty auth JSON when no config.json exists."""
        with patch("pathlib.Path.home", return_value=tmp_path):
            result = _load_registry_auth("ubuntu:22.04")

        decoded = json.loads(base64.b64decode(result))
        assert decoded == {}

    def test_no_matching_auth_returns_empty(self, tmp_path):
        """Returns empty auth when registry has no matching entry."""
        creds = base64.b64encode(b"user:pass").decode()
        self._make_docker_config(tmp_path, {
            "ghcr.io": {"auth": creds},
        })
        with patch("pathlib.Path.home", return_value=tmp_path):
            # Request auth for Docker Hub, but only ghcr.io is configured
            result = _load_registry_auth("ubuntu:22.04")

        decoded = json.loads(base64.b64decode(result))
        assert decoded == {}

    def test_docker_hub_domain_alias(self, tmp_path):
        """Auth keyed as 'docker.io' is found for Docker Hub images."""
        creds = base64.b64encode(b"aliasuser:aliaspass").decode()
        self._make_docker_config(tmp_path, {
            "docker.io": {"auth": creds},
        })
        with patch("pathlib.Path.home", return_value=tmp_path):
            result = _load_registry_auth("ubuntu:22.04")

        decoded = json.loads(base64.b64decode(result))
        assert decoded["username"] == "aliasuser"
        assert decoded["password"] == "aliaspass"


# ====================================================================== #
#  DockerClient.image_inspect                                              #
# ====================================================================== #


class TestDockerClientImageInspect:
    """DockerClient.image_inspect over the real Docker socket."""

    def test_inspect_existing_image(self):
        """image_inspect returns a dict for an existing image."""
        _requires_docker()
        client = DockerClient()
        # Ensure alpine:3.19 is present (use API, skip on rate limit)
        if not client.image_exists("alpine:3.19"):
            try:
                client.image_pull("alpine:3.19")
            except DockerAPIError:
                pytest.skip("Docker pull rate-limited")
        info = client.image_inspect("alpine:3.19")
        assert isinstance(info, dict)
        assert "Id" in info
        assert info["Id"].startswith("sha256:")
        assert "Config" in info
        assert "RootFS" in info

    def test_inspect_missing_image_raises(self):
        """image_inspect raises ImageNotFoundError for nonexistent image."""
        _requires_docker()
        client = DockerClient()
        with pytest.raises(ImageNotFoundError) as exc_info:
            client.image_inspect("nitrobox-nonexistent-test-image:v99.99.99")
        assert exc_info.value.status == 404
        assert "nitrobox-nonexistent-test-image" in exc_info.value.image


# ====================================================================== #
#  DockerClient.image_exists                                               #
# ====================================================================== #


class TestDockerClientImageExists:
    """DockerClient.image_exists checks."""

    def test_existing_image_returns_true(self):
        """image_exists returns True for an image that is present."""
        _requires_docker()
        client = DockerClient()
        if not client.image_exists("alpine:3.19"):
            try:
                client.image_pull("alpine:3.19")
            except DockerAPIError:
                pytest.skip("Docker pull rate-limited")
        assert client.image_exists("alpine:3.19") is True

    def test_missing_image_returns_false(self):
        """image_exists returns False for a nonexistent image."""
        _requires_docker()
        client = DockerClient()
        assert client.image_exists("nitrobox-nonexistent-test-image:v99.99.99") is False


# ====================================================================== #
#  DockerClient.image_pull                                                 #
# ====================================================================== #


class TestDockerClientImagePull:
    """DockerClient.image_pull from a real registry."""

    def test_pull_small_image(self):
        """Pulls alpine:3.19 successfully via the Docker API."""
        _requires_docker()
        client = DockerClient()
        # Remove if present to force a real pull
        try:
            client.image_remove("alpine:3.19", force=True)
        except DockerAPIError:
            pass

        try:
            client.image_pull("alpine:3.19")
        except DockerAPIError as e:
            # Docker daemon wraps registry 429 as a 500; skip on any
            # pull failure since we're testing client logic, not registry.
            pytest.skip(f"Docker pull failed (likely rate-limited): {e}")
        assert client.image_exists("alpine:3.19")

    def test_pull_with_separate_tag(self):
        """Pull using image and tag as separate components."""
        _requires_docker()
        client = DockerClient()
        try:
            client.image_remove("alpine:3.19", force=True)
        except DockerAPIError:
            pass

        try:
            client.image_pull("alpine", tag="3.19")
        except DockerAPIError as e:
            pytest.skip(f"Docker pull failed (likely rate-limited): {e}")
        assert client.image_exists("alpine:3.19")

    def test_pull_nonexistent_image_raises(self):
        """Pulling a nonexistent image raises DockerAPIError."""
        _requires_docker()
        client = DockerClient()
        with pytest.raises(DockerAPIError):
            client.image_pull(
                "nitrobox-nonexistent-test-image:v99.99.99",
                timeout=30,
            )


# ====================================================================== #
#  DockerClient.image_save                                                 #
# ====================================================================== #


class TestDockerClientImageSave:
    """DockerClient.image_save streams image as tar."""

    def test_save_returns_readable_tar(self):
        """image_save returns a streaming response that can be read as tar."""
        _requires_docker()
        client = DockerClient()
        if not client.image_exists("alpine:3.19"):
            try:
                client.image_pull("alpine:3.19")
            except DockerAPIError:
                pytest.skip("Docker pull rate-limited")

        resp = client.image_save("alpine:3.19")
        # Should be able to open as a streaming tar
        with tarfile.open(fileobj=resp, mode="r|") as tar:
            members = []
            for member in tar:
                members.append(member.name)
                if len(members) >= 5:
                    break  # Don't read the whole thing, just verify it works
        assert len(members) > 0
        # Docker save tarballs contain manifest.json
        # (may not be in the first 5 entries, so just check we got members)

    def test_save_missing_image_raises(self):
        """image_save raises ImageNotFoundError for nonexistent image."""
        _requires_docker()
        client = DockerClient()
        with pytest.raises(ImageNotFoundError):
            client.image_save("nitrobox-nonexistent-test-image:v99.99.99")


# ====================================================================== #
#  Rust py_parse_image_ref                                                 #
# ====================================================================== #


class TestRustParseImageRef:
    """Rust-based image reference parsing via py_parse_image_ref.

    These tests don't require Docker or network access.
    """

    @staticmethod
    def _parse(image: str) -> tuple[str, str, str]:
        _requires_rust_parse_image_ref()
        from nitrobox._core import py_parse_image_ref
        return py_parse_image_ref(image)

    @pytest.mark.parametrize(
        "image, expected_domain, expected_repo, expected_tag",
        [
            ("ubuntu:22.04", "docker.io", "library/ubuntu", "22.04"),
            ("ghcr.io/org/repo:v1", "ghcr.io", "org/repo", "v1"),
            ("alexgshaw/repo:tag", "docker.io", "alexgshaw/repo", "tag"),
            ("localhost:5000/img:v1", "localhost:5000", "img", "v1"),
            ("ubuntu", "docker.io", "library/ubuntu", "latest"),
            ("docker.io/library/python:3.13", "docker.io", "library/python", "3.13"),
            ("python", "docker.io", "library/python", "latest"),
            ("ghcr.io/org/sub/repo:latest", "ghcr.io", "org/sub/repo", "latest"),
            ("myregistry:5000/myimage", "myregistry:5000", "myimage", "latest"),
            ("python:3.11-slim", "docker.io", "library/python", "3.11-slim"),
        ],
        ids=[
            "ubuntu_with_tag",
            "ghcr_with_tag",
            "docker_hub_user_repo",
            "localhost_with_port",
            "bare_name",
            "docker_io_explicit_library",
            "implicit_latest_tag",
            "nested_repo_path",
            "custom_registry_with_port_no_tag",
            "slim_tag",
        ],
    )
    def test_parse_image_ref(self, image, expected_domain, expected_repo, expected_tag):
        domain, repo, tag = self._parse(image)
        assert domain == expected_domain
        assert repo == expected_repo
        assert tag == expected_tag


# ====================================================================== #
#  Rust image store: py_image_store_get/put/clear                          #
# ====================================================================== #


class TestRustImageStore:
    """In-memory image config cache (Rust ImageStore).

    No Docker or network access needed.
    """

    def setup_method(self):
        """Clear the store before each test to avoid cross-contamination."""
        if not _has_rust_image_store():
            return
        from nitrobox._core import py_image_store_clear
        py_image_store_clear()

    def teardown_method(self):
        """Clear the store after each test."""
        if not _has_rust_image_store():
            return
        from nitrobox._core import py_image_store_clear
        py_image_store_clear()

    def test_get_returns_none_for_missing(self):
        """py_image_store_get returns None for an image not in the store."""
        _requires_rust_image_store()
        from nitrobox._core import py_image_store_get
        assert py_image_store_get("nonexistent:latest") is None

    def test_put_and_get_roundtrip(self):
        """Store a config, retrieve it, and verify fields."""
        _requires_rust_image_store()
        from nitrobox._core import py_image_store_get, py_image_store_put

        config = {
            "image_id": "sha256:abc123",
            "diff_ids": ["sha256:layer1", "sha256:layer2"],
            "cmd": ["/bin/bash"],
            "entrypoint": None,
            "env": {"PATH": "/usr/bin", "HOME": "/root"},
            "working_dir": "/app",
            "exposed_ports": [8080, 443],
        }
        py_image_store_put("myimage:v1", json.dumps(config))

        raw = py_image_store_get("myimage:v1")
        assert raw is not None
        result = json.loads(raw)
        assert result["image_id"] == "sha256:abc123"
        assert result["diff_ids"] == ["sha256:layer1", "sha256:layer2"]
        assert result["cmd"] == ["/bin/bash"]
        assert result["entrypoint"] is None
        assert result["env"]["PATH"] == "/usr/bin"
        assert result["working_dir"] == "/app"
        assert result["exposed_ports"] == [8080, 443]

    def test_put_indexes_by_image_id(self):
        """Config is also retrievable by image_id (digest)."""
        _requires_rust_image_store()
        from nitrobox._core import py_image_store_get, py_image_store_put

        config = {
            "image_id": "sha256:deadbeef",
            "diff_ids": [],
            "cmd": None,
            "entrypoint": None,
            "env": {},
            "working_dir": None,
            "exposed_ports": [],
        }
        py_image_store_put("alpine:3.19", json.dumps(config))

        # Retrieve by name
        raw_by_name = py_image_store_get("alpine:3.19")
        assert raw_by_name is not None

        # Retrieve by image_id
        raw_by_id = py_image_store_get("sha256:deadbeef")
        assert raw_by_id is not None

        # Both should return the same config
        assert json.loads(raw_by_name) == json.loads(raw_by_id)

    def test_clear_removes_all_entries(self):
        """py_image_store_clear empties the store."""
        _requires_rust_image_store()
        from nitrobox._core import (
            py_image_store_clear,
            py_image_store_get,
            py_image_store_put,
        )

        config = json.dumps({
            "image_id": "sha256:aaa",
            "diff_ids": [],
            "cmd": None,
            "entrypoint": None,
            "env": {},
            "working_dir": None,
            "exposed_ports": [],
        })
        py_image_store_put("img1:v1", config)
        py_image_store_put("img2:v2", config)

        assert py_image_store_get("img1:v1") is not None
        assert py_image_store_get("img2:v2") is not None

        py_image_store_clear()

        assert py_image_store_get("img1:v1") is None
        assert py_image_store_get("img2:v2") is None

    def test_put_invalid_json_raises(self):
        """py_image_store_put raises ValueError on invalid JSON."""
        _requires_rust_image_store()
        from nitrobox._core import py_image_store_put

        with pytest.raises(ValueError):
            py_image_store_put("bad:v1", "not valid json {{{")

    def test_put_overwrites_existing(self):
        """Storing under the same name overwrites the previous entry."""
        _requires_rust_image_store()
        from nitrobox._core import py_image_store_get, py_image_store_put

        config_v1 = json.dumps({
            "image_id": "sha256:v1",
            "diff_ids": ["sha256:old"],
            "cmd": ["/bin/sh"],
            "entrypoint": None,
            "env": {},
            "working_dir": None,
            "exposed_ports": [],
        })
        config_v2 = json.dumps({
            "image_id": "sha256:v2",
            "diff_ids": ["sha256:new"],
            "cmd": ["/bin/bash"],
            "entrypoint": None,
            "env": {},
            "working_dir": None,
            "exposed_ports": [],
        })

        py_image_store_put("myimg:latest", config_v1)
        py_image_store_put("myimg:latest", config_v2)

        raw = py_image_store_get("myimg:latest")
        result = json.loads(raw)
        assert result["image_id"] == "sha256:v2"
        assert result["cmd"] == ["/bin/bash"]


# ====================================================================== #
#  Integration: registry-first path (rootfs.py)                            #
# ====================================================================== #


class TestRegistryFirstIntegration:
    """Integration tests for the registry-first image resolution path.

    These tests verify that get_image_config and _get_image_diff_ids
    work correctly using the registry (without Docker).
    """

    def setup_method(self):
        """Clear image store to ensure clean state."""
        if not _has_rust_image_store():
            return
        from nitrobox._core import py_image_store_clear
        py_image_store_clear()

    def teardown_method(self):
        if not _has_rust_image_store():
            return
        from nitrobox._core import py_image_store_clear
        py_image_store_clear()

    def test_get_image_config_from_registry(self):
        """get_image_config returns correct config fetched from registry."""
        _skip_if_no_registry()
        from nitrobox.rootfs import get_image_config

        config = get_image_config("alpine:3.19")
        assert config is not None
        assert "cmd" in config
        assert "env" in config
        assert "working_dir" in config
        assert "exposed_ports" in config
        # Alpine has CMD ["/bin/sh"]
        assert config["cmd"] is not None
        assert isinstance(config["env"], dict)
        assert "PATH" in config["env"]

    def test_get_image_config_populates_store(self):
        """get_image_config populates the Rust ImageStore for subsequent lookups."""
        _requires_rust_image_store()
        _skip_if_no_registry()
        from nitrobox._core import py_image_store_get
        from nitrobox.rootfs import get_image_config

        # First call: hits registry
        config1 = get_image_config("alpine:3.19")
        assert config1 is not None

        # Verify store was populated
        raw = py_image_store_get("alpine:3.19")
        assert raw is not None
        cached = json.loads(raw)
        assert cached["cmd"] == config1["cmd"]

        # Second call: should hit the store (verify by checking it returns same data)
        config2 = get_image_config("alpine:3.19")
        assert config2 is not None
        assert config2["cmd"] == config1["cmd"]

    def test_get_image_diff_ids_from_registry(self):
        """_get_image_diff_ids returns diff_ids fetched from registry."""
        _skip_if_no_registry()
        from nitrobox.rootfs import _get_image_diff_ids

        diff_ids = _get_image_diff_ids("alpine:3.19")
        assert diff_ids is not None
        assert len(diff_ids) >= 1
        assert all(d.startswith("sha256:") for d in diff_ids)

    def test_get_image_config_returns_none_for_invalid(self):
        """get_image_config returns None for an image that doesn't exist anywhere."""
        from nitrobox.rootfs import get_image_config

        # Use a fake registry and image that definitely doesn't exist
        # Patch out the registry call to return None and Docker to fail
        with patch("nitrobox.image.docker.get_client") as mock_get_client:
            mock_client = MagicMock()
            mock_client.image_inspect.side_effect = Exception("no docker")
            mock_get_client.return_value = mock_client

            with patch(
                "nitrobox.image.registry.get_image_metadata_from_registry",
                side_effect=RuntimeError("fake registry error"),
            ):
                config = get_image_config("totally-fake-registry.invalid/nope:v1")
        assert config is None

    def test_prepare_rootfs_layers_registry_path(self, tmp_path):
        """prepare_rootfs_layers_from_docker downloads layers from registry."""
        _skip_if_no_registry()
        from nitrobox.rootfs import prepare_rootfs_layers_from_docker

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        # This should use the registry-first path (no Docker pull needed)
        layer_dirs = prepare_rootfs_layers_from_docker(
            "alpine:3.19",
            cache_dir,
            pull=False,  # Don't require Docker pull
        )

        assert len(layer_dirs) >= 1
        # Each layer dir should exist and contain real filesystem content
        for d in layer_dirs:
            assert d.exists(), f"Layer dir missing: {d}"
            assert d.is_dir()
        # At least one layer should have typical rootfs content
        has_content = any(
            (d / "bin").exists() or (d / "usr").exists()
            for d in layer_dirs
        )
        assert has_content, "No layer contained expected rootfs content (bin/ or usr/)"

    def test_prepare_rootfs_layers_uses_cache(self, tmp_path):
        """Second call to prepare_rootfs_layers_from_docker uses cached layers."""
        _skip_if_no_registry()
        from nitrobox.rootfs import prepare_rootfs_layers_from_docker

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        # First extraction
        dirs1 = prepare_rootfs_layers_from_docker("alpine:3.19", cache_dir, pull=False)
        # Second extraction should use cache (much faster)
        dirs2 = prepare_rootfs_layers_from_docker("alpine:3.19", cache_dir, pull=False)

        assert dirs1 == dirs2
        # All layer dirs should still exist
        for d in dirs2:
            assert d.exists()


# ====================================================================== #
#  DockerClient with mocked socket (unit tests)                            #
# ====================================================================== #


class TestDockerClientUnit:
    """Unit tests for DockerClient that mock the socket connection."""

    def test_image_inspect_404_raises_image_not_found(self):
        """image_inspect wraps HTTP 404 into ImageNotFoundError."""
        client = DockerClient.__new__(DockerClient)
        client._socket_path = "/dev/null"

        mock_resp = MagicMock()
        mock_resp.status = 404
        mock_resp.read.return_value = b'{"message": "No such image"}'

        with patch.object(client, "_request", return_value=mock_resp):
            with pytest.raises(ImageNotFoundError) as exc_info:
                client.image_inspect("missing:latest")
            assert exc_info.value.image == "missing:latest"

    def test_image_inspect_500_raises_docker_api_error(self):
        """image_inspect wraps HTTP 500 into DockerAPIError."""
        client = DockerClient.__new__(DockerClient)
        client._socket_path = "/dev/null"

        mock_resp = MagicMock()
        mock_resp.status = 500
        mock_resp.read.return_value = b'{"message": "internal error"}'

        with patch.object(client, "_request", return_value=mock_resp):
            with pytest.raises(DockerAPIError) as exc_info:
                client.image_inspect("bad:latest")
            assert exc_info.value.status == 500

    def test_image_exists_true_on_200(self):
        """image_exists returns True when image_inspect succeeds."""
        client = DockerClient.__new__(DockerClient)
        client._socket_path = "/dev/null"

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"Id": "sha256:abc", "Config": {}}'

        with patch.object(client, "_request", return_value=mock_resp):
            assert client.image_exists("present:v1") is True

    def test_image_exists_false_on_404(self):
        """image_exists returns False when image is not found."""
        client = DockerClient.__new__(DockerClient)
        client._socket_path = "/dev/null"

        mock_resp = MagicMock()
        mock_resp.status = 404
        mock_resp.read.return_value = b'{"message": "No such image"}'

        with patch.object(client, "_request", return_value=mock_resp):
            assert client.image_exists("missing:v1") is False

    def test_image_save_404_raises(self):
        """image_save raises ImageNotFoundError on 404."""
        client = DockerClient.__new__(DockerClient)
        client._socket_path = "/dev/null"

        mock_resp = MagicMock()
        mock_resp.status = 404
        mock_resp.read.return_value = b""

        with patch.object(client, "_request", return_value=mock_resp):
            with pytest.raises(ImageNotFoundError):
                client.image_save("gone:v1")

    def test_json_request_raises_on_error(self):
        """_json_request raises DockerAPIError for >= 400 status."""
        client = DockerClient.__new__(DockerClient)
        client._socket_path = "/dev/null"

        mock_resp = MagicMock()
        mock_resp.status = 409
        mock_resp.read.return_value = b'{"message": "conflict"}'

        with patch.object(client, "_request", return_value=mock_resp):
            with pytest.raises(DockerAPIError) as exc_info:
                client._json_request("DELETE", "/images/test")
            assert exc_info.value.status == 409
            assert "conflict" in exc_info.value.message
