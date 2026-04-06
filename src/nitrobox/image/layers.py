"""Layer management via containers/storage — zero-copy overlayfs layers.

Images are stored in containers/storage (same as podman). Layers are
accessed directly as overlay diff directories — no copying or extraction.
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


# ====================================================================== #
#  containers/storage read (pure Python — reads JSON metadata)            #
# ====================================================================== #


def _containers_storage_root() -> Path | None:
    """Return the containers/storage graph root, or None if not configured."""
    p = os.environ.get("CONTAINERS_STORAGE_ROOT", "")
    if p:
        return Path(p)
    home = Path.home()
    default = home / ".local/share/containers/storage"
    if default.exists():
        return default
    return None


def _try_containers_storage(image_name: str) -> list[Path] | None:
    """Get layer paths from containers/storage (zero-copy, pure Python).

    Reads the store's JSON metadata files directly. Returns None if the
    image isn't in the store.
    """
    graph_root = _containers_storage_root()
    if graph_root is None:
        return None

    try:
        # Detect driver from directory structure
        driver = None
        for d in ("overlay", "vfs"):
            if (graph_root / f"{d}-images").is_dir():
                driver = d
                break
        if driver is None:
            return None

        images_file = graph_root / f"{driver}-images" / "images.json"
        layers_file = graph_root / f"{driver}-layers" / "layers.json"
        if not images_file.exists() or not layers_file.exists():
            return None

        images = json.loads(images_file.read_text())
        layers_data = json.loads(layers_file.read_text())

        # Build layer parent map
        layer_parent: dict[str, str] = {}
        for layer in layers_data:
            layer_parent[layer["id"]] = layer.get("parent", "")

        # Find image by name
        top_layer = None
        for img in images:
            for name in img.get("names", []):
                if name == image_name or name.endswith("/" + image_name):
                    top_layer = img.get("layer", "")
                    break
            if top_layer:
                break
        if not top_layer:
            return None

        # Walk layer chain top→bottom, then reverse for bottom→top
        chain: list[str] = []
        lid = top_layer
        while lid:
            chain.append(lid)
            lid = layer_parent.get(lid, "")
        chain.reverse()

        # Build paths
        paths: list[Path] = []
        for lid in chain:
            if driver == "vfs":
                p = graph_root / "vfs" / "dir" / lid
            else:
                p = graph_root / driver / lid / "diff"
            if not p.is_dir():
                return None
            paths.append(p)

        logger.info("containers/storage: %s has %d layers (zero-copy)",
                     image_name, len(paths))
        return paths

    except Exception as e:
        logger.debug("containers/storage read failed: %s", e)
        return None


# ====================================================================== #
#  containers/storage pull (via nitrobox-core image-pull in userns)       #
# ====================================================================== #


def _containers_storage_pull(image_name: str) -> bool:
    """Pull an image into containers/storage via nitrobox-core image-pull."""
    bin_path = os.environ.get("NITROBOX_CORE_BIN", "")
    if not bin_path:
        candidate = Path(__file__).resolve().parent.parent.parent / "go" / "nitrobox-core"
        if candidate.is_file():
            bin_path = str(candidate)
    if not bin_path:
        return False

    from nitrobox.config import detect_subuid_range
    subuid = detect_subuid_range()
    if not subuid:
        return False

    outer_uid, sub_start, sub_count = subuid
    outer_gid = os.getgid()

    graph_root = _containers_storage_root()
    if graph_root is None:
        graph_root = Path.home() / ".local/share/containers/storage"
        graph_root.mkdir(parents=True, exist_ok=True)
        os.environ["CONTAINERS_STORAGE_ROOT"] = str(graph_root)

    run_root = Path(f"/tmp/nitrobox-containers-run-{os.getuid()}")
    run_root.mkdir(parents=True, exist_ok=True)

    req = json.dumps({
        "image": image_name,
        "graph_root": str(graph_root),
        "run_root": str(run_root),
    }).encode()

    # Fork + unshare(CLONE_NEWUSER) + newuidmap + exec image-pull
    import ctypes
    userns_r, userns_w = os.pipe()
    go_r, go_w = os.pipe()
    json_r, json_w = os.pipe()

    pid = os.fork()
    if pid == 0:
        os.close(userns_r); os.close(go_w); os.close(json_w)
        os.environ["_CONTAINERS_ROOTLESS_UID"] = str(outer_uid)
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        if libc.unshare(0x10000000) != 0:
            os._exit(1)
        os.write(userns_w, b"R"); os.close(userns_w)
        os.read(go_r, 1); os.close(go_r)
        os.dup2(json_r, 0); os.close(json_r)
        os.execvp(bin_path, [bin_path, "image-pull"])
        os._exit(127)

    os.close(userns_w); os.close(go_r); os.close(json_r)
    os.read(userns_r, 1); os.close(userns_r)

    subprocess.run(
        ["newuidmap", str(pid), "0", str(outer_uid), "1", "1", str(sub_start), str(sub_count)],
        check=False, capture_output=True,
    )
    subprocess.run(
        ["newgidmap", str(pid), "0", str(outer_gid), "1", "1", str(sub_start), str(sub_count)],
        check=False, capture_output=True,
    )

    os.write(go_w, b"G"); os.close(go_w)
    os.write(json_w, req); os.close(json_w)

    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status) == 0


# ====================================================================== #
#  Public API                                                              #
# ====================================================================== #


def prepare_rootfs_layers_from_docker(
    image_name: str,
    cache_dir: Path,
    pull: bool = True,
) -> list[Path]:
    """Get image layers as directories for overlayfs stacking.

    Uses containers/storage for zero-copy layer access:
      1. Check if image exists in store → return diff paths directly
      2. Pull from registry into store → return diff paths

    Args:
        image_name: Image reference (e.g. ``"ubuntu:22.04"``).
        cache_dir: Unused (kept for API compatibility).
        pull: If True, pull from registry when image not in store.

    Returns:
        Ordered list of layer directories (bottom to top).
    """
    # 1. Check containers/storage
    layers = _try_containers_storage(image_name)
    if layers is not None:
        logger.info("Layer cache ready for %s: %d layers (zero-copy)",
                     image_name, len(layers))
        return layers

    # 2. Pull into store
    if pull:
        logger.info("Pulling %s into containers/storage", image_name)
        if not _containers_storage_pull(image_name):
            raise RuntimeError(
                f"Failed to pull {image_name!r} into containers/storage. "
                f"Check network connectivity and image name."
            )

        layers = _try_containers_storage(image_name)
        if layers is not None:
            logger.info("Layer cache ready for %s: %d layers (zero-copy)",
                         image_name, len(layers))
            return layers

    raise RuntimeError(f"Image {image_name!r} not found in containers/storage.")


# ====================================================================== #
#  Layer locking (for concurrent sandbox safety)                           #
# ====================================================================== #


def acquire_layer_locks(layer_dirs: list[Path]) -> list[int]:
    """Acquire shared (read) locks on layer directories."""
    fds: list[int] = []
    for d in layer_dirs:
        lock_path = d.parent / f".{d.name}.lock"
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o644)
        fcntl.flock(fd, fcntl.LOCK_SH)
        fds.append(fd)
    return fds


def release_layer_locks(lock_fds: list[int]) -> None:
    """Release previously acquired layer locks."""
    for fd in lock_fds:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        except OSError:
            pass


def remove_layer_locked(layer_dir: Path) -> None:
    """Remove a layer directory with exclusive lock."""
    lock_path = layer_dir.parent / f".{layer_dir.name}.lock"
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        rmtree_mapped(layer_dir)
    except BlockingIOError:
        logger.debug("Layer %s locked by another process, skipping", layer_dir.name)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


# ====================================================================== #
#  Cleanup                                                                 #
# ====================================================================== #


def rmtree_mapped(path: str | Path) -> None:
    """Remove a directory that may contain files with mapped UIDs.

    Sandbox overlay upper dirs have files owned by mapped UIDs
    (e.g. host uid 493316). Regular rmtree fails on these —
    we fork into a userns with the same UID mapping to delete as root.
    """
    path = Path(path)
    if not path.exists():
        return

    try:
        shutil.rmtree(path)
        return
    except PermissionError:
        pass

    _rmtree_in_userns(path)


def _rmtree_in_userns(path: Path) -> None:
    """Fork into userns with full UID mapping and rm -rf."""
    import ctypes
    from nitrobox.config import detect_subuid_range

    subuid = detect_subuid_range()
    if not subuid:
        shutil.rmtree(path, ignore_errors=True)
        return

    outer_uid, sub_start, sub_count = subuid
    outer_gid = os.getgid()

    userns_r, userns_w = os.pipe()
    go_r, go_w = os.pipe()

    pid = os.fork()
    if pid == 0:
        os.close(userns_r)
        os.close(go_w)
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        libc.unshare(0x10000000)  # CLONE_NEWUSER
        os.write(userns_w, b"R")
        os.close(userns_w)
        os.read(go_r, 1)
        os.close(go_r)
        shutil.rmtree(path, ignore_errors=True)
        os._exit(0)

    os.close(userns_w)
    os.close(go_r)
    os.read(userns_r, 1)
    os.close(userns_r)
    subprocess.run(
        ["newuidmap", str(pid), "0", str(outer_uid), "1", "1", str(sub_start), str(sub_count)],
        check=False, capture_output=True,
    )
    subprocess.run(
        ["newgidmap", str(pid), "0", str(outer_gid), "1", "1", str(sub_start), str(sub_count)],
        check=False, capture_output=True,
    )
    os.write(go_w, b"G")
    os.close(go_w)
    os.waitpid(pid, 0)


# ====================================================================== #
#  Image resolution helpers                                                #
# ====================================================================== #


def resolve_base_rootfs(
    image: str,
    rootfs_cache_dir: Path,
    fs_backend: str = "overlayfs",
) -> tuple[Path, list[Path] | None]:
    """Resolve the base rootfs for a sandbox."""
    candidate = Path(image)
    if candidate.exists() and candidate.is_dir():
        return candidate, None

    import time
    t0 = time.monotonic()
    layer_dirs = prepare_rootfs_layers_from_docker(image, rootfs_cache_dir, pull=True)
    elapsed_ms = (time.monotonic() - t0) * 1000
    logger.info("Layer cache ready (%.1fms): %s (%d layers)",
                elapsed_ms, image, len(layer_dirs))
    return layer_dirs[0], layer_dirs


def _get_image_digest(image: str) -> str | None:
    """Get image digest from containers/storage.

    Returns ``sha256_<hex>`` format for cache key compatibility.
    Falls back to Docker API if containers/storage doesn't have the image.
    """
    graph_root = _containers_storage_root()
    if graph_root is not None:
        try:
            for d in ("overlay", "vfs"):
                images_file = graph_root / f"{d}-images" / "images.json"
                if not images_file.exists():
                    continue
                for img in json.loads(images_file.read_text()):
                    for name in img.get("names", []):
                        if name == image or name.endswith("/" + image):
                            raw_id = img.get("id", "")
                            return f"sha256_{raw_id[:64]}" if raw_id else None
        except Exception:
            pass

    # Fallback: try Docker API (for images built by docker but not yet in our store)
    try:
        from nitrobox.image.docker import get_client, ImageNotFoundError
        info = get_client().image_inspect(image)
        digest = info.get("Id", "")
        return digest.replace(":", "_")[:80] if digest else None
    except Exception:
        return None


def _resolve_cached_rootfs(
    image: str,
    rootfs_cache_dir: Path,
    prepare_fn,
    *,
    verify_fn=None,
    label: str = "rootfs",
) -> Path:
    """Resolve a flat rootfs with file-lock-based caching."""
    candidate = Path(image)
    if candidate.exists() and candidate.is_dir():
        if verify_fn:
            verify_fn(candidate)
        return candidate

    digest = _get_image_digest(image)
    cache_key = digest if digest else image.replace("/", "_").replace(":", "_").replace(".", "_")
    cached_rootfs = rootfs_cache_dir / cache_key

    if cached_rootfs.exists() and cached_rootfs.is_dir():
        if verify_fn:
            verify_fn(cached_rootfs)
        return cached_rootfs

    import time
    lock_path = rootfs_cache_dir / f".{cache_key}.lock"
    rootfs_cache_dir.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "w") as lock_fd:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        try:
            if cached_rootfs.exists() and cached_rootfs.is_dir():
                if verify_fn:
                    verify_fn(cached_rootfs)
                return cached_rootfs

            t0 = time.monotonic()
            prepare_fn(image, cached_rootfs)
            elapsed_ms = (time.monotonic() - t0) * 1000
            logger.info("Auto-prepared %s (%.1fms): %s -> %s",
                        label, elapsed_ms, image, cached_rootfs)
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
    return cached_rootfs


def resolve_btrfs_rootfs(image: str, rootfs_cache_dir: Path) -> Path:
    """Resolve flat rootfs for btrfs backend."""
    raise NotImplementedError("btrfs backend not supported with containers/storage")


def resolve_flat_rootfs(image: str, rootfs_cache_dir: Path) -> Path:
    """Resolve flat rootfs via container export."""
    raise NotImplementedError("flat rootfs not supported with containers/storage")
