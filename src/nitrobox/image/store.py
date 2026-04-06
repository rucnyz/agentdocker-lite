"""Image config cache: in-memory (Rust ImageStore) + disk manifest cache."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import TypedDict

logger = logging.getLogger(__name__)


# ====================================================================== #
#  Image config type + parsing helpers                                     #
# ====================================================================== #


class ImageConfig(TypedDict, total=False):
    """OCI/Docker image configuration.

    Used as the canonical format throughout nitrobox for image metadata.
    Produced by :func:`get_image_config`, persisted in the manifest
    cache, and consumed by :func:`_apply_image_defaults`.
    """
    cmd: list[str] | None
    entrypoint: list[str] | None
    env: dict[str, str]
    working_dir: str | None
    exposed_ports: list[int]
    diff_ids: list[str]


def _parse_docker_env(env_list: list[str] | None) -> dict[str, str]:
    """Convert Docker ``Env`` list (``["K=V", ...]``) to dict."""
    result: dict[str, str] = {}
    for entry in env_list or []:
        key, _, value = entry.partition("=")
        result[key] = value
    return result


def _parse_docker_ports(exposed_ports: dict | None) -> list[int]:
    """Convert Docker ``ExposedPorts`` (``{"8080/tcp": {}, ...}``) to ``[8080, ...]``."""
    result: list[int] = []
    for port_proto in exposed_ports or {}:
        try:
            result.append(int(port_proto.split("/")[0]))
        except (ValueError, IndexError):
            pass
    return result


def _docker_inspect_to_config(info: dict) -> ImageConfig:
    """Convert a Docker API ``/images/{id}/json`` response to :class:`ImageConfig`."""
    config = info.get("Config") or {}
    return ImageConfig(
        cmd=config.get("Cmd"),
        entrypoint=config.get("Entrypoint"),
        env=_parse_docker_env(config.get("Env")),
        working_dir=config.get("WorkingDir") or None,
        exposed_ports=_parse_docker_ports(config.get("ExposedPorts")),
        diff_ids=info.get("RootFS", {}).get("Layers", []),
    )


# ====================================================================== #
#  Docker layer-level caching                                              #
# ====================================================================== #


def _safe_cache_key(diff_id: str) -> str:
    """Convert a diff_id like 'sha256:abc...' to a filesystem-safe key.

    Uses the full 64-char hex hash.  The new mount API (``fsconfig``)
    has a ~256-byte limit per ``lowerdir+`` parameter, but a typical
    path like ``~/.cache/nitrobox/rootfs/layers/<64chars>`` is ~90
    bytes — well within the limit.

    Podman uses random IDs for layer directories; we use the full
    diff_id hash for content-addressable deduplication.
    """
    # "sha256:abcdef..." → "abcdef..."
    _, _, hexpart = diff_id.partition(":")
    return hexpart if hexpart else diff_id.replace(":", "_")


# ====================================================================== #
#  Image metadata (CLI detection, diff-IDs, config)                        #
# ====================================================================== #


def _get_image_diff_ids(image_name: str) -> list[str]:
    """Get layer diff_ids: ImageStore → registry → Docker API.

    Also caches the full image config (WORKDIR, CMD, etc.) in the
    ImageStore so that subsequent ``get_image_config()`` calls never
    need a second registry round-trip.

    Raises ``RuntimeError`` with a descriptive message (including root
    causes from each failed source) if all sources fail.
    """
    # 1. Rust in-memory store (~0ms)
    cached = _image_store_get(image_name)
    if cached and cached.get("diff_ids"):
        return cached["diff_ids"]

    errors: list[tuple[str, Exception]] = []

    # 2. Docker API — fastest for locally cached images (~5ms)
    from nitrobox.image.docker import get_client
    try:
        info = get_client().image_inspect(image_name)
        config = _docker_inspect_to_config(info)
        diff_ids = config.get("diff_ids")
        if diff_ids:
            _image_store_populate(image_name, config)
            return diff_ids
    except Exception as exc:
        errors.append(("docker", exc))

    # 3. Registry API — fallback for images not in local Docker (~100ms)
    from nitrobox.image.registry import get_image_metadata_from_registry
    try:
        metadata = get_image_metadata_from_registry(image_name)
        if metadata.get("diff_ids"):
            _image_store_populate(image_name, metadata)
            return metadata["diff_ids"]
    except Exception as exc:
        errors.append(("registry", exc))

    detail = "; ".join(f"{src}: {exc}" for src, exc in errors)
    raise RuntimeError(
        f"Cannot get image metadata for {image_name!r} [{detail}]"
    )


def get_image_config(image_name: str) -> dict | None:
    """Extract CMD, ENTRYPOINT, ENV, WORKDIR from a Docker/OCI image.

    Resolution order:
      1. Rust in-memory ImageStore (~0ms)
      2. Disk manifest cache — persisted config from prior rootfs prep
      3. Docker API — fast for locally cached images (~5ms)
      4. Registry API — fallback for images not in Docker (~100ms)

    Returns a dict with keys: ``cmd``, ``entrypoint``, ``env``,
    ``working_dir``, ``exposed_ports``.  Returns ``None`` only when
    no source has the image at all (e.g. typo in image name).
    """
    # 1. Rust in-memory store (~0ms)
    cached = _image_store_get(image_name)
    if cached is not None:
        return cached

    # 2. Disk manifest cache — populated by prepare_rootfs_layers_from_docker
    disk_cfg = _read_config_from_manifest_cache(image_name)
    if disk_cfg is not None:
        _image_store_populate(image_name, disk_cfg)
        return disk_cfg

    # 3. Docker API — fast for locally cached images (~5ms)
    from nitrobox.image.docker import get_client
    try:
        info = get_client().image_inspect(image_name)
        result = _docker_inspect_to_config(info)
        _image_store_populate(image_name, result)
        return result
    except Exception:
        pass

    # 4. Registry API — fallback for images not in Docker (~100ms)
    from nitrobox.image.registry import get_image_metadata_from_registry
    try:
        metadata = get_image_metadata_from_registry(image_name)
        _image_store_populate(image_name, metadata)
        return metadata
    except Exception:
        pass

    return None


# -- Disk config cache ------------------------------------------------ #

def _read_config_from_manifest_cache(image_name: str) -> dict | None:
    """Read image config from the on-disk manifest cache.

    The manifest cache lives alongside the rootfs layer cache and is
    populated by ``prepare_rootfs_layers_from_docker``.  Since the
    manifest is written during rootfs extraction (which succeeds even
    when the registry is rate-limited on subsequent calls), this
    provides a reliable local source for WORKDIR/CMD/ENV.
    """
    cache_dir = _default_rootfs_cache_dir()
    if cache_dir is None:
        return None
    manifests_dir = cache_dir / "manifests"
    if not manifests_dir.exists():
        return None

    safe_name = image_name.replace("/", "_").replace(":", "_").replace(".", "_")
    for path in [manifests_dir / f"{safe_name}.json"]:
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text())
            cfg = data.get("config")
            if cfg and cfg.get("working_dir") is not None:
                return cfg
        except (json.JSONDecodeError, OSError):
            pass
    return None


def _default_rootfs_cache_dir() -> Path | None:
    """Return the default rootfs cache directory."""
    cache_home = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    d = Path(cache_home) / "nitrobox" / "rootfs"
    return d if d.exists() else None


# -- ImageStore helpers ------------------------------------------------ #

def _image_store_get(image_name: str) -> ImageConfig | None:
    """Look up image config in Rust in-memory store."""
    try:
        from nitrobox._backend import py_image_store_get
        raw = py_image_store_get(image_name)
        if raw is None:
            return None
        data = json.loads(raw)
        return ImageConfig(
            cmd=data.get("cmd"),
            entrypoint=data.get("entrypoint"),
            env=data.get("env", {}),
            working_dir=data.get("working_dir"),
            exposed_ports=data.get("exposed_ports", []),
            diff_ids=data.get("diff_ids", []),
        )
    except Exception as exc:
        logger.debug("ImageStore lookup failed for %s: %s", image_name, exc)
        return None


def _image_store_populate(image_name: str, config: ImageConfig) -> None:
    """Populate Rust ImageStore from an :class:`ImageConfig`."""
    try:
        from nitrobox._backend import py_image_store_put
        payload = json.dumps({
            "image_id": "",
            "diff_ids": config.get("diff_ids", []),
            "cmd": config.get("cmd"),
            "entrypoint": config.get("entrypoint"),
            "env": config.get("env", {}),
            "working_dir": config.get("working_dir"),
            "exposed_ports": config.get("exposed_ports", []),
        })
        py_image_store_put(image_name, payload)
    except Exception as exc:
        logger.debug("Failed to populate image store for %s: %s", image_name, exc)


def _get_image_digest(image_name: str) -> str | None:
    """Get the content digest of a Docker image for cache keying."""
    from nitrobox.image.docker import get_client
    try:
        info = get_client().image_inspect(image_name)
        digest = info.get("Id", "")
        return digest.replace(":", "_")[:80] if digest else None
    except Exception:
        return None


def _get_manifest_diff_ids(
    cache_dir: Path,
    image_name: str,
) -> list[str] | None:
    """Read cached manifest to get diff_ids without docker inspect.

    Checks both digest-based and name-based manifest keys so that
    images with different tags but identical content (e.g. different
    compose project names) share the same cached layer set.

    If the manifest also contains a ``config`` section (WORKDIR, CMD,
    etc.), it is loaded into the in-memory ImageStore so that
    ``get_image_config()`` can find it without a registry call.
    """
    manifests_dir = cache_dir / "manifests"

    def _try_load(path: Path) -> list[str] | None:
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return None
        # Populate ImageStore from persisted config (if present)
        cfg = data.get("config")
        if cfg:
            merged = dict(cfg)
            merged["diff_ids"] = data.get("diff_ids", [])
            _image_store_populate(image_name, merged)
        return data.get("diff_ids")

    # Try digest-based key first (content-addressable)
    digest = _get_image_digest(image_name)
    if digest:
        result = _try_load(manifests_dir / f"{digest}.json")
        if result is not None:
            return result

    # Fall back to name-based key (backward compat)
    safe_name = image_name.replace("/", "_").replace(":", "_").replace(".", "_")
    return _try_load(manifests_dir / f"{safe_name}.json")


def _write_manifest(
    cache_dir: Path,
    image_name: str,
    diff_ids: list[str],
    image_config: dict | None = None,
) -> None:
    """Write manifest mapping image to its layer diff_ids and config.

    Writes under both the digest-based key and the name-based key
    so that future lookups by either tag or digest hit the cache.

    The optional *image_config* dict (cmd, entrypoint, env,
    working_dir, exposed_ports) is persisted alongside diff_ids so
    that ``get_image_config()`` can read it from disk without a
    registry round-trip.  This mirrors Podman's approach of storing
    the OCI config blob locally after pull.
    """
    manifests_dir = cache_dir / "manifests"
    manifests_dir.mkdir(parents=True, exist_ok=True)

    data: dict = {
        "image": image_name,
        "diff_ids": diff_ids,
        "layers": [_safe_cache_key(did) for did in diff_ids],
    }
    if image_config:
        data["config"] = {
            "cmd": image_config.get("cmd"),
            "entrypoint": image_config.get("entrypoint"),
            "env": image_config.get("env", {}),
            "working_dir": image_config.get("working_dir"),
            "exposed_ports": image_config.get("exposed_ports", []),
        }
    payload = json.dumps(data, indent=2)

    # Write name-based manifest
    safe_name = image_name.replace("/", "_").replace(":", "_").replace(".", "_")
    (manifests_dir / f"{safe_name}.json").write_text(payload)

    # Write digest-based manifest (content-addressable)
    digest = _get_image_digest(image_name)
    if digest and digest != safe_name:
        (manifests_dir / f"{digest}.json").write_text(payload)
