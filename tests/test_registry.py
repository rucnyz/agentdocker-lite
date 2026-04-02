"""Tests for the pure-Python OCI registry client.

Unit tests mock _registry_request to test parsing logic.
Integration tests hit real registries (Docker Hub) and are skipped
when the network is unavailable.
"""

from __future__ import annotations

import hashlib
import json
from unittest.mock import patch

import pytest

from nitrobox._registry import (
    get_config_from_registry,
    get_image_config_from_registry,
    get_manifest,
    parse_image_ref,
    pull_image_layers,
)


# ====================================================================== #
#  parse_image_ref — pure logic, no mock needed                            #
# ====================================================================== #


class TestParseImageRef:
    """Image reference string parsing."""

    def test_bare_name(self):
        reg, repo, tag = parse_image_ref("ubuntu")
        assert reg == "registry-1.docker.io"
        assert repo == "library/ubuntu"
        assert tag == "latest"

    def test_name_with_tag(self):
        reg, repo, tag = parse_image_ref("ubuntu:22.04")
        assert reg == "registry-1.docker.io"
        assert repo == "library/ubuntu"
        assert tag == "22.04"

    def test_name_with_org(self):
        reg, repo, tag = parse_image_ref("nvidia/cuda:12.0-base")
        assert reg == "registry-1.docker.io"
        assert repo == "nvidia/cuda"
        assert tag == "12.0-base"

    def test_ghcr(self):
        reg, repo, tag = parse_image_ref("ghcr.io/org/repo:v1")
        assert reg == "ghcr.io"
        assert repo == "org/repo"
        assert tag == "v1"

    def test_custom_registry_with_port(self):
        reg, repo, tag = parse_image_ref("myregistry:5000/myimage")
        assert reg == "myregistry:5000"
        assert repo == "myimage"
        assert tag == "latest"

    def test_custom_registry_with_port_and_tag(self):
        reg, repo, tag = parse_image_ref("myregistry:5000/myimage:v2")
        assert reg == "myregistry:5000"
        assert repo == "myimage"
        assert tag == "v2"

    def test_localhost(self):
        reg, repo, tag = parse_image_ref("localhost/myapp:dev")
        assert reg == "localhost"
        assert repo == "myapp"
        assert tag == "dev"

    def test_nested_repo(self):
        reg, repo, tag = parse_image_ref("ghcr.io/org/sub/repo:latest")
        assert reg == "ghcr.io"
        assert repo == "org/sub/repo"
        assert tag == "latest"

    def test_implicit_latest(self):
        _, _, tag = parse_image_ref("python")
        assert tag == "latest"

    def test_slim_tag(self):
        reg, repo, tag = parse_image_ref("python:3.11-slim")
        assert reg == "registry-1.docker.io"
        assert repo == "library/python"
        assert tag == "3.11-slim"


# ====================================================================== #
#  Manifest parsing — mock _registry_request                               #
# ====================================================================== #

# Realistic manifest list (Docker Hub style)
_MANIFEST_LIST = {
    "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
    "manifests": [
        {
            "digest": "sha256:amd64digest",
            "platform": {"os": "linux", "architecture": "amd64"},
        },
        {
            "digest": "sha256:arm64digest",
            "platform": {"os": "linux", "architecture": "arm64"},
        },
    ],
}

# Realistic image manifest
_IMAGE_MANIFEST = {
    "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
    "config": {
        "digest": "sha256:configdigest",
        "size": 1234,
    },
    "layers": [
        {"digest": "sha256:layer1digest", "size": 10000},
        {"digest": "sha256:layer2digest", "size": 20000},
    ],
}

# Realistic image config
_IMAGE_CONFIG = {
    "config": {
        "Cmd": ["/bin/bash"],
        "Entrypoint": None,
        "Env": ["PATH=/usr/local/bin:/usr/bin", "LANG=C.UTF-8"],
        "WorkingDir": "/app",
        "ExposedPorts": {"8080/tcp": {}},
    },
    "rootfs": {
        "type": "layers",
        "diff_ids": [
            "sha256:aaaa",
            "sha256:bbbb",
        ],
    },
}


class TestGetManifest:
    """Manifest fetching and manifest list resolution."""

    def test_direct_manifest(self):
        """Non-list manifest is returned as-is."""
        with patch("nitrobox._registry._registry_request") as mock_req:
            mock_req.return_value = json.dumps(_IMAGE_MANIFEST).encode()
            result = get_manifest("registry-1.docker.io", "library/ubuntu", "22.04", "token")
        assert result["config"]["digest"] == "sha256:configdigest"
        assert len(result["layers"]) == 2

    def test_manifest_list_resolves_amd64(self):
        """Manifest list resolves to linux/amd64 platform."""
        call_count = 0

        def mock_request(registry, path, token, accept=None):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return json.dumps(_MANIFEST_LIST).encode()
            else:
                # Second call: fetch resolved manifest by digest
                assert "sha256:amd64digest" in path or "sha256:arm64digest" in path
                return json.dumps(_IMAGE_MANIFEST).encode()

        with patch("nitrobox._registry._registry_request", side_effect=mock_request):
            with patch("platform.machine", return_value="x86_64"):
                result = get_manifest("registry-1.docker.io", "library/ubuntu", "22.04", "token")
        assert result == _IMAGE_MANIFEST
        assert call_count == 2

    def test_manifest_list_no_matching_arch_raises(self):
        """Manifest list with no matching architecture raises."""
        with patch("nitrobox._registry._registry_request") as mock_req:
            mock_req.return_value = json.dumps(_MANIFEST_LIST).encode()
            with patch("platform.machine", return_value="riscv64"):
                with pytest.raises(RuntimeError, match="No linux/riscv64"):
                    get_manifest("registry-1.docker.io", "library/ubuntu", "22.04", "token")


class TestGetImageConfig:
    """Image config download and parsing."""

    def test_config_parsing(self):
        """Config blob is downloaded and parsed correctly."""
        with patch("nitrobox._registry._registry_request") as mock_req:
            mock_req.return_value = json.dumps(_IMAGE_CONFIG).encode()
            result = get_image_config_from_registry(
                "registry-1.docker.io", "library/ubuntu",
                _IMAGE_MANIFEST, "token",
            )
        assert result["config"]["Cmd"] == ["/bin/bash"]
        assert result["rootfs"]["diff_ids"] == ["sha256:aaaa", "sha256:bbbb"]
        # Verify it requested the right blob
        mock_req.assert_called_once()
        call_path = mock_req.call_args[0][1]
        assert "sha256:configdigest" in call_path


class TestGetConfigFromRegistry:
    """High-level get_config_from_registry (end-to-end parsing)."""

    def test_extracts_cmd_env_workdir(self):
        """Extracts CMD, ENV, WORKDIR, exposed ports from config."""
        call_count = 0

        def mock_request(registry, path, token, accept=None):
            nonlocal call_count
            call_count += 1
            if "manifests" in path:
                return json.dumps(_IMAGE_MANIFEST).encode()
            else:
                return json.dumps(_IMAGE_CONFIG).encode()

        with patch("nitrobox._registry._registry_request", side_effect=mock_request):
            with patch("nitrobox._registry._get_token", return_value="faketoken"):
                result = get_config_from_registry("ubuntu:22.04")

        assert result is not None
        assert result["cmd"] == ["/bin/bash"]
        assert result["entrypoint"] is None
        assert result["env"]["PATH"] == "/usr/local/bin:/usr/bin"
        assert result["env"]["LANG"] == "C.UTF-8"
        assert result["working_dir"] == "/app"
        assert result["exposed_ports"] == [8080]

    def test_returns_none_on_failure(self):
        """Returns None when registry is unreachable."""
        with patch("nitrobox._registry._get_token", side_effect=OSError("no network")):
            result = get_config_from_registry("nonexistent:latest")
        assert result is None


# ====================================================================== #
#  Layer download + digest verification                                    #
# ====================================================================== #


class TestPullImageLayers:
    """Layer download with SHA256 digest verification."""

    def _make_layer(self, content: bytes) -> tuple[str, str, bytes]:
        """Create a fake layer with matching digest."""
        digest = "sha256:" + hashlib.sha256(content).hexdigest()
        diff_id = "sha256:" + hashlib.sha256(b"diff-" + content).hexdigest()
        return diff_id, digest, content

    def test_downloads_needed_layers(self):
        """Only downloads layers in needed_diff_ids set."""
        layer1_content = b"layer1-content-bytes"
        layer2_content = b"layer2-content-bytes"
        diff1, digest1, blob1 = self._make_layer(layer1_content)
        diff2, digest2, blob2 = self._make_layer(layer2_content)

        manifest = {
            "config": {"digest": "sha256:cfg"},
            "layers": [
                {"digest": digest1, "size": len(blob1)},
                {"digest": digest2, "size": len(blob2)},
            ],
        }
        config = {"rootfs": {"diff_ids": [diff1, diff2]}}

        def mock_request(registry, path, token, accept=None):
            if "manifests" in path:
                return json.dumps(manifest).encode()
            elif "sha256:cfg" in path:
                return json.dumps(config).encode()
            elif digest1.split(":")[1] in path:
                return blob1
            elif digest2.split(":")[1] in path:
                return blob2
            raise ValueError(f"unexpected path: {path}")

        with patch("nitrobox._registry._registry_request", side_effect=mock_request):
            with patch("nitrobox._registry._get_token", return_value="tok"):
                # Only request layer 1
                result = pull_image_layers(f"test:v1", {diff1})

        assert diff1 in result
        assert diff2 not in result
        assert result[diff1] == blob1

    def test_digest_mismatch_raises(self):
        """Corrupted download (wrong SHA256) raises RuntimeError."""
        content = b"real-content"
        diff_id = "sha256:diff"
        correct_digest = "sha256:" + hashlib.sha256(content).hexdigest()

        manifest = {
            "config": {"digest": "sha256:cfg"},
            "layers": [{"digest": correct_digest, "size": len(content)}],
        }
        config = {"rootfs": {"diff_ids": [diff_id]}}

        def mock_request(registry, path, token, accept=None):
            if "manifests" in path:
                return json.dumps(manifest).encode()
            elif "sha256:cfg" in path:
                return json.dumps(config).encode()
            else:
                return b"corrupted-content"  # wrong data

        with patch("nitrobox._registry._registry_request", side_effect=mock_request):
            with patch("nitrobox._registry._get_token", return_value="tok"):
                with pytest.raises(RuntimeError, match="digest mismatch"):
                    pull_image_layers("test:v1", {diff_id})

    def test_layer_count_mismatch_raises(self):
        """Mismatched manifest layers vs config diff_ids raises."""
        manifest = {
            "config": {"digest": "sha256:cfg"},
            "layers": [{"digest": "sha256:a", "size": 1}],
        }
        config = {"rootfs": {"diff_ids": ["sha256:x", "sha256:y"]}}  # 2 vs 1

        def mock_request(registry, path, token, accept=None):
            if "manifests" in path:
                return json.dumps(manifest).encode()
            else:
                return json.dumps(config).encode()

        with patch("nitrobox._registry._registry_request", side_effect=mock_request):
            with patch("nitrobox._registry._get_token", return_value="tok"):
                with pytest.raises(RuntimeError, match="layer count mismatch"):
                    pull_image_layers("test:v1", {"sha256:x"})


# ====================================================================== #
#  Integration tests — real network (skipped if offline)                   #
# ====================================================================== #


def _skip_if_no_registry():
    """Skip test if Docker Hub API is unreachable or rate-limited."""
    import urllib.error
    from nitrobox._registry import get_diff_ids_from_registry
    try:
        if get_diff_ids_from_registry("alpine:3.19") is None:
            pytest.skip("Docker Hub unreachable or rate-limited")
    except (OSError, urllib.error.URLError, RuntimeError):
        pytest.skip("Docker Hub unreachable or rate-limited")


class TestRegistryIntegration:
    """Real registry tests (Docker Hub)."""

    def test_parse_and_get_config_ubuntu(self):
        """Fetch real ubuntu image config from Docker Hub."""
        _skip_if_no_registry()
        result = get_config_from_registry("ubuntu:22.04")
        assert result is not None
        assert result["cmd"] is not None  # ubuntu has CMD ["/bin/bash"]
        assert "PATH" in result["env"]

    def test_parse_and_get_config_python(self):
        """Fetch real python image config."""
        _skip_if_no_registry()
        result = get_config_from_registry("python:3.11-slim")
        assert result is not None
        assert "python" in (result.get("cmd") or [""])[0].lower() or result.get("entrypoint") is not None
        assert result["working_dir"] is not None or result["cmd"] is not None

    def test_get_diff_ids(self):
        """Fetch diff_ids for a real image."""
        _skip_if_no_registry()
        from nitrobox._registry import get_diff_ids_from_registry
        diff_ids = get_diff_ids_from_registry("alpine:3.19")
        assert diff_ids is not None
        assert len(diff_ids) >= 1
        assert all(d.startswith("sha256:") for d in diff_ids)

    def test_pull_layer_with_digest_verify(self):
        """Download a real layer and verify digest."""
        _skip_if_no_registry()
        from nitrobox._registry import (
            _get_token,
            download_layer,
            get_image_config_from_registry,
        )
        registry, repo, tag = parse_image_ref("alpine:3.19")
        token = _get_token(registry, repo)
        manifest = get_manifest(registry, repo, tag, token)
        config = get_image_config_from_registry(registry, repo, manifest, token)

        # Download first layer
        layer_desc = manifest["layers"][0]
        blob = download_layer(registry, repo, layer_desc["digest"], token)
        actual_digest = "sha256:" + hashlib.sha256(blob).hexdigest()
        assert actual_digest == layer_desc["digest"]
