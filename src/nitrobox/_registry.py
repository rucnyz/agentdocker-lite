"""Pure-Python OCI registry client — zero external dependencies.

Downloads Docker/OCI images directly from container registries
(Docker Hub, ghcr.io, etc.) without requiring Docker or Podman.

Uses only stdlib: urllib, json, hashlib, tarfile.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

# Default registry and endpoints
_DOCKER_HUB = "registry-1.docker.io"
_DOCKER_AUTH = "https://auth.docker.io/token"

# Accept headers for manifest
_MANIFEST_ACCEPT = ", ".join([
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
])


def parse_image_ref(image: str) -> tuple[str, str, str]:
    """Parse image reference into (registry, repository, tag).

    Examples::

        "ubuntu:22.04"          → ("registry-1.docker.io", "library/ubuntu", "22.04")
        "python:3.11-slim"      → ("registry-1.docker.io", "library/python", "3.11-slim")
        "ghcr.io/org/repo:v1"   → ("ghcr.io", "org/repo", "v1")
        "myregistry:5000/img"   → ("myregistry:5000", "img", "latest")
    """
    tag = "latest"
    # Split tag
    if ":" in image and not image.rsplit(":", 1)[-1].startswith("/"):
        # Could be tag or port. If after last ":" looks like a tag (no "/"), it's a tag
        parts = image.rsplit(":", 1)
        if "/" not in parts[1]:
            image, tag = parts

    # Split registry from repository
    # A registry contains "." or ":" or is "localhost"
    if "/" in image:
        first, rest = image.split("/", 1)
        if "." in first or ":" in first or first == "localhost":
            return first, rest, tag
        # No registry prefix — Docker Hub
        return _DOCKER_HUB, image, tag

    # Bare name like "ubuntu" → Docker Hub library image
    return _DOCKER_HUB, f"library/{image}", tag


def _get_token(registry: str, repo: str) -> str | None:
    """Get bearer token for registry authentication."""
    if registry == _DOCKER_HUB:
        url = f"{_DOCKER_AUTH}?service=registry.docker.io&scope=repository:{repo}:pull"
    else:
        # Try token endpoint from WWW-Authenticate header
        try:
            urllib.request.urlopen(f"https://{registry}/v2/", timeout=5)
            return None  # No auth needed
        except urllib.error.HTTPError as e:
            if e.code != 401:
                return None
            auth_header = e.headers.get("WWW-Authenticate", "")
            # Parse: Bearer realm="...",service="...",scope="..."
            realm = re.search(r'realm="([^"]+)"', auth_header)
            service = re.search(r'service="([^"]+)"', auth_header)
            if not realm:
                return None
            url = f"{realm.group(1)}?service={service.group(1) if service else ''}&scope=repository:{repo}:pull"
        except (OSError, urllib.error.URLError):
            return None

    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            return data.get("token") or data.get("access_token")
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as e:
        logger.debug("Token request failed: %s", e)
        return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Don't follow redirects — handle them manually to drop auth headers."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _registry_request(
    registry: str, path: str, token: str | None,
    accept: str | None = None,
) -> bytes:
    """Make authenticated request to registry API.

    Handles Docker Hub redirects: blob requests return 307 to CDN,
    and the CDN rejects Authorization headers. We follow redirects
    manually without auth.
    """
    url = f"https://{registry}{path}"
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if accept:
        req.add_header("Accept", accept)

    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=120) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 307, 308):
            # Follow redirect WITHOUT auth header (CDN rejects it)
            redirect_url = e.headers.get("Location")
            if redirect_url:
                with urllib.request.urlopen(redirect_url, timeout=120) as resp:
                    return resp.read()
        raise


def get_manifest(
    registry: str, repo: str, tag: str, token: str | None,
) -> dict[str, Any]:
    """Get image manifest, resolving manifest lists to amd64/linux."""
    data = _registry_request(
        registry, f"/v2/{repo}/manifests/{tag}", token,
        accept=_MANIFEST_ACCEPT,
    )
    manifest = json.loads(data)

    # If it's a manifest list / OCI index, resolve to linux/amd64
    media_type = manifest.get("mediaType", "")
    if "list" in media_type or "index" in media_type:
        import platform
        arch = platform.machine()
        arch_map = {"x86_64": "amd64", "aarch64": "arm64"}
        target_arch = arch_map.get(arch, arch)

        for m in manifest.get("manifests", []):
            p = m.get("platform", {})
            if p.get("os") == "linux" and p.get("architecture") == target_arch:
                # Fetch the actual manifest
                digest = m["digest"]
                data = _registry_request(
                    registry, f"/v2/{repo}/manifests/{digest}", token,
                    accept=_MANIFEST_ACCEPT,
                )
                return json.loads(data)
        raise RuntimeError(
            f"No linux/{target_arch} manifest found for {repo}:{tag}"
        )

    return manifest


def get_image_config_from_registry(
    registry: str, repo: str, manifest: dict, token: str | None,
) -> dict[str, Any]:
    """Download and parse the image config blob."""
    config_digest = manifest["config"]["digest"]
    data = _registry_request(
        registry, f"/v2/{repo}/blobs/{config_digest}", token,
    )
    return json.loads(data)


def get_diff_ids_from_registry(image: str) -> list[str] | None:
    """Get layer diff_ids from registry (without Docker)."""
    try:
        registry, repo, tag = parse_image_ref(image)
        token = _get_token(registry, repo)
        manifest = get_manifest(registry, repo, tag, token)
        config = get_image_config_from_registry(registry, repo, manifest, token)
        rootfs = config.get("rootfs", {})
        return rootfs.get("diff_ids")
    except (OSError, urllib.error.URLError, RuntimeError, KeyError) as e:
        logger.debug("Registry diff_ids failed for %s: %s", image, e)
        return None


def download_layer(
    registry: str, repo: str, digest: str, token: str | None,
) -> bytes:
    """Download a single layer blob from the registry."""
    return _registry_request(
        registry, f"/v2/{repo}/blobs/{digest}", token,
    )


def pull_image_layers(
    image: str,
    needed_diff_ids: set[str],
) -> dict[str, bytes]:
    """Download layer blobs from registry for the given diff_ids.

    Returns a dict mapping diff_id → raw layer tarball bytes.
    Only downloads layers whose diff_id is in ``needed_diff_ids``.
    """
    registry, repo, tag = parse_image_ref(image)
    token = _get_token(registry, repo)
    manifest = get_manifest(registry, repo, tag, token)
    config = get_image_config_from_registry(registry, repo, manifest, token)

    diff_ids = config.get("rootfs", {}).get("diff_ids", [])
    layers = manifest.get("layers", [])

    if len(diff_ids) != len(layers):
        raise RuntimeError(
            f"Manifest/config layer count mismatch: {len(layers)} vs {len(diff_ids)}"
        )

    result: dict[str, bytes] = {}
    for diff_id, layer_desc in zip(diff_ids, layers):
        if diff_id not in needed_diff_ids:
            continue
        digest = layer_desc["digest"]
        size_mb = layer_desc.get("size", 0) / 1024 / 1024
        logger.info("Downloading layer %.1fMB: %s", size_mb, diff_id[:20])
        blob = download_layer(registry, repo, digest, token)

        # Verify digest
        actual = "sha256:" + hashlib.sha256(blob).hexdigest()
        if actual != digest:
            raise RuntimeError(
                f"Layer digest mismatch: expected {digest}, got {actual}"
            )
        result[diff_id] = blob

    return result


def get_config_from_registry(image: str) -> dict | None:
    """Get image config (CMD, ENV, WORKDIR, etc.) from registry.

    Returns same format as rootfs.get_image_config().
    """
    try:
        registry, repo, tag = parse_image_ref(image)
        token = _get_token(registry, repo)
        manifest = get_manifest(registry, repo, tag, token)
        config = get_image_config_from_registry(registry, repo, manifest, token)

        container_config = config.get("config", {})
        env_list = container_config.get("Env") or []
        env_dict = {}
        for entry in env_list:
            k, _, v = entry.partition("=")
            env_dict[k] = v

        exposed = container_config.get("ExposedPorts") or {}
        ports = []
        for port_spec in exposed:
            try:
                ports.append(int(port_spec.split("/")[0]))
            except (ValueError, IndexError):
                pass

        return {
            "cmd": container_config.get("Cmd"),
            "entrypoint": container_config.get("Entrypoint"),
            "env": env_dict,
            "working_dir": container_config.get("WorkingDir") or None,
            "exposed_ports": ports or None,
        }
    except (OSError, urllib.error.URLError, RuntimeError, KeyError) as e:
        logger.debug("Registry config failed for %s: %s", image, e)
        return None
