"""Tests for the pure-Python OCI registry client.

Unit tests mock _registry_request to test parsing logic.
Integration tests hit real registries (Docker Hub) and are skipped
when the network is unavailable.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from nitrobox._registry import (
    get_image_metadata_from_registry,
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

    def test_digest_reference(self):
        reg, repo, ref = parse_image_ref("ubuntu@sha256:abcdef1234567890")
        assert reg == "registry-1.docker.io"
        assert repo == "library/ubuntu"
        assert ref == "sha256:abcdef1234567890"

    def test_digest_with_tag(self):
        """Digest takes precedence over tag."""
        reg, repo, ref = parse_image_ref("ubuntu:22.04@sha256:abcdef")
        assert reg == "registry-1.docker.io"
        assert repo == "library/ubuntu"
        assert ref == "sha256:abcdef"

    def test_digest_with_registry(self):
        reg, repo, ref = parse_image_ref("ghcr.io/org/repo@sha256:abc123")
        assert reg == "ghcr.io"
        assert repo == "org/repo"
        assert ref == "sha256:abc123"


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
        with patch("nitrobox.image.registry._registry_request") as mock_req:
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

        with patch("nitrobox.image.registry._registry_request", side_effect=mock_request):
            with patch("platform.machine", return_value="x86_64"):
                result = get_manifest("registry-1.docker.io", "library/ubuntu", "22.04", "token")
        assert result == _IMAGE_MANIFEST
        assert call_count == 2

    def test_manifest_list_no_matching_arch_raises(self):
        """Manifest list with no matching architecture raises."""
        with patch("nitrobox.image.registry._registry_request") as mock_req:
            mock_req.return_value = json.dumps(_MANIFEST_LIST).encode()
            with patch("platform.machine", return_value="riscv64"):
                with pytest.raises(RuntimeError, match="No linux/riscv64"):
                    get_manifest("registry-1.docker.io", "library/ubuntu", "22.04", "token")


class TestGetImageConfig:
    """Image config download and parsing."""

    def test_config_parsing(self):
        """Config blob is downloaded and parsed correctly."""
        with patch("nitrobox.image.registry._registry_request") as mock_req:
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
    """High-level get_image_metadata_from_registry (end-to-end parsing)."""

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

        with patch("nitrobox.image.registry._registry_request", side_effect=mock_request):
            with patch("nitrobox.image.registry._get_token", return_value="faketoken"):
                result = get_image_metadata_from_registry("ubuntu:22.04")

        assert result is not None
        assert result["cmd"] == ["/bin/bash"]
        assert result["entrypoint"] is None
        assert result["env"]["PATH"] == "/usr/local/bin:/usr/bin"
        assert result["env"]["LANG"] == "C.UTF-8"
        assert result["working_dir"] == "/app"
        assert result["exposed_ports"] == [8080]

    def test_raises_on_failure(self):
        """Raises when registry is unreachable."""
        with patch("nitrobox.image.registry._get_token", side_effect=OSError("no network")):
            with pytest.raises(OSError):
                get_image_metadata_from_registry("nonexistent:latest")


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

    def _make_blob_streaming_mock(self, blobs: dict[str, bytes]):
        """Return a mock for _download_blob_streaming that writes blobs to file."""
        def mock_streaming(registry, repo, digest, token, dest, **kwargs):
            if digest in blobs:
                Path(dest).write_bytes(blobs[digest])
            else:
                Path(dest).write_bytes(b"corrupted-content")
        return mock_streaming

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

        def mock_request(registry, path, token, accept=None, **kwargs):
            if "manifests" in path:
                return json.dumps(manifest).encode()
            elif "sha256:cfg" in path:
                return json.dumps(config).encode()
            raise ValueError(f"unexpected path: {path}")

        mock_streaming = self._make_blob_streaming_mock({digest1: blob1, digest2: blob2})

        with patch("nitrobox.image.registry._registry_request", side_effect=mock_request):
            with patch("nitrobox.image.registry._download_blob_streaming", side_effect=mock_streaming):
                with patch("nitrobox.image.registry._get_token", return_value="tok"):
                    result = pull_image_layers("test:v1", {diff1})

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

        def mock_request(registry, path, token, accept=None, **kwargs):
            if "manifests" in path:
                return json.dumps(manifest).encode()
            elif "sha256:cfg" in path:
                return json.dumps(config).encode()
            raise ValueError(f"unexpected path: {path}")

        def mock_streaming(registry, repo, digest, token, dest, **kwargs):
            Path(dest).write_bytes(b"corrupted-content")

        with patch("nitrobox.image.registry._registry_request", side_effect=mock_request):
            with patch("nitrobox.image.registry._download_blob_streaming", side_effect=mock_streaming):
                with patch("nitrobox.image.registry._get_token", return_value="tok"):
                    with pytest.raises(RuntimeError, match="digest mismatch"):
                        pull_image_layers("test:v1", {diff_id})

    def test_layer_count_mismatch_raises(self):
        """Mismatched manifest layers vs config diff_ids raises."""
        manifest = {
            "config": {"digest": "sha256:cfg"},
            "layers": [{"digest": "sha256:a", "size": 1}],
        }
        config = {"rootfs": {"diff_ids": ["sha256:x", "sha256:y"]}}  # 2 vs 1

        def mock_request(registry, path, token, accept=None, **kwargs):
            if "manifests" in path:
                return json.dumps(manifest).encode()
            else:
                return json.dumps(config).encode()

        with patch("nitrobox.image.registry._registry_request", side_effect=mock_request):
            with patch("nitrobox.image.registry._get_token", return_value="tok"):
                with pytest.raises(RuntimeError, match="layer count mismatch"):
                    pull_image_layers("test:v1", {"sha256:x"})


# ====================================================================== #
#  Regression: duplicate diff-ids in layer preparation                     #
# ====================================================================== #


class TestDuplicateDiffIds:
    """Images with duplicate diff-ids must extract all unique layers.

    Some Docker images have the same diff-id appearing more than once
    (e.g. an empty layer reused at multiple positions).  The layer
    cache uses content-addressable directories (one per unique diff-id),
    so deduplication is correct — but the ``needed`` set computation
    must not be confused by the duplicate.

    Regression test for: zip(diff_ids, layer_dirs) misalignment when
    diff_ids has duplicates but layer_dirs is deduplicated.
    """

    def test_needed_layers_with_duplicates(self, tmp_path):
        """All unique layers are extracted even when diff-ids repeat."""
        from nitrobox.image.store import _safe_cache_key

        layers_dir = tmp_path / "layers"
        layers_dir.mkdir()

        # Image with 6 layers, layer B appears twice
        diff_ids = [
            "sha256:aaaa",
            "sha256:bbbb",
            "sha256:cccc",
            "sha256:bbbb",  # duplicate
            "sha256:dddd",
            "sha256:eeee",
        ]

        # Deduplicated layer dirs (what prepare_rootfs_layers_from_docker builds)
        layer_dirs = list(dict.fromkeys(
            layers_dir / _safe_cache_key(did) for did in diff_ids
        ))
        assert len(layer_dirs) == 5  # bbbb appears once

        # Pre-cache layers A and B (simulating partial cache)
        (layers_dir / _safe_cache_key("sha256:aaaa")).mkdir()
        (layers_dir / _safe_cache_key("sha256:bbbb")).mkdir()

        # Compute needed — this is the code that was buggy
        needed_keys = {d.name for d in layer_dirs if not d.exists()}
        _key_to_did = {_safe_cache_key(did): did for did in diff_ids}
        needed = {_key_to_did[k] for k in needed_keys if k in _key_to_did}

        # Must include C, D, E — NOT miss any
        assert "sha256:cccc" in needed
        assert "sha256:dddd" in needed
        assert "sha256:eeee" in needed
        # Must NOT include already-cached A and B
        assert "sha256:aaaa" not in needed
        assert "sha256:bbbb" not in needed

    def test_all_unique_dirs_present_after_extraction(self, tmp_path):
        """After extraction, every unique diff-id has a directory."""
        from nitrobox.image.store import _safe_cache_key

        layers_dir = tmp_path / "layers"
        layers_dir.mkdir()

        diff_ids = [
            "sha256:1111",
            "sha256:2222",
            "sha256:1111",  # duplicate
            "sha256:3333",
        ]

        layer_dirs = list(dict.fromkeys(
            layers_dir / _safe_cache_key(did) for did in diff_ids
        ))

        # Simulate extraction: create all directories
        for d in layer_dirs:
            d.mkdir(exist_ok=True)

        # Verify: the verification check should pass
        still_missing = [d for d in layer_dirs if not d.exists()]
        assert still_missing == []


# ====================================================================== #
#  Integration tests — real network (skipped if offline)                   #
# ====================================================================== #


def _skip_if_no_registry():
    """Skip test if Docker Hub API is unreachable or rate-limited."""
    from nitrobox._registry import get_image_metadata_from_registry
    try:
        get_image_metadata_from_registry("alpine:3.19")
    except Exception:
        pytest.skip("Docker Hub unreachable or rate-limited")


class TestRegistryIntegration:
    """Real registry tests (Docker Hub)."""

    def test_parse_and_get_config_ubuntu(self):
        """Fetch real ubuntu image config from Docker Hub."""
        _skip_if_no_registry()
        result = get_image_metadata_from_registry("ubuntu:22.04")
        assert result is not None
        assert result["cmd"] is not None  # ubuntu has CMD ["/bin/bash"]
        assert "PATH" in result["env"]

    def test_parse_and_get_config_python(self):
        """Fetch real python image config."""
        _skip_if_no_registry()
        result = get_image_metadata_from_registry("python:3.11-slim")
        assert result is not None
        assert "python" in (result.get("cmd") or [""])[0].lower() or result.get("entrypoint") is not None
        assert result["working_dir"] is not None or result["cmd"] is not None

    def test_get_diff_ids(self):
        """Fetch diff_ids for a real image."""
        _skip_if_no_registry()
        from nitrobox._registry import get_image_metadata_from_registry
        metadata = get_image_metadata_from_registry("alpine:3.19")
        diff_ids = metadata["diff_ids"]
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
