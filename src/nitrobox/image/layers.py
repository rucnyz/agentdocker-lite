"""Layer extraction, caching, and rootfs preparation from Docker images."""

from __future__ import annotations

import fcntl
import io
import json
import logging
import os
import subprocess
import tarfile
import time
from pathlib import Path
from typing import Any

from nitrobox.image.docker import get_client
from nitrobox.image.store import (
    _safe_cache_key,
    _get_image_diff_ids,
    _image_store_get,
    _write_manifest,
    _get_manifest_diff_ids,
)

logger = logging.getLogger(__name__)


# ====================================================================== #
#  Persistent storage userns (Podman's "pause process" pattern)            #
# ====================================================================== #
#
# Podman runs its ENTIRE storage subsystem inside a user namespace
# (via BecomeRootInUserNS + a pause process that keeps the namespace
# alive).  All file operations happen as UID 0 inside the namespace,
# so os.RemoveAll() just works — no ownership mismatches.
#
# We replicate this with a module-level sentinel process:
#   - Lazily created on first use (fork + unshare + newuidmap)
#   - Holds a userns with full UID/GID mapping
#   - All destructive storage operations (rm, extract) nsenter into it
#   - Cleaned up on process exit via atexit


class _StorageNS:
    """Persistent user namespace for the storage subsystem.

    Equivalent to Podman's pause process: a long-lived sentinel that
    holds a user namespace.  Layer extraction and cache cleanup enter
    this namespace via nsenter, avoiding the need to create a new
    userns per operation.
    """

    _instance: _StorageNS | None = None
    _pid: int | None = None

    @classmethod
    def get(cls) -> _StorageNS | None:
        """Return the singleton, creating it lazily.  None if rootful or no subuid."""
        if os.geteuid() == 0:
            return None
        if cls._instance is not None:
            if cls._instance.alive:
                return cls._instance
            cls._instance = None  # sentinel died, recreate
        from nitrobox.config import detect_subuid_range
        subuid = detect_subuid_range()
        if not subuid:
            return None
        inst = cls()
        inst._start(subuid)
        cls._instance = inst
        return inst

    def _start(self, subuid: tuple[int, int, int]) -> None:
        outer_uid, sub_start, sub_count = subuid
        outer_gid = os.getgid()

        self._sentinel = subprocess.Popen(
            ["unshare", "--user", "--fork", "--", "sleep", "infinity"],
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Wait for the child to enter the new userns.
        my_userns = os.readlink("/proc/self/ns/user")
        for _ in range(1000):
            try:
                child_userns = os.readlink(f"/proc/{self._sentinel.pid}/ns/user")
                if child_userns != my_userns:
                    break
            except (FileNotFoundError, PermissionError):
                pass
            time.sleep(0.001)
        else:
            self._sentinel.kill()
            self._sentinel.wait()
            raise RuntimeError("Timeout waiting for storage userns sentinel")

        # Set up full UID/GID mapping.
        subprocess.run(
            ["newuidmap", str(self._sentinel.pid),
             "0", str(outer_uid), "1",
             "1", str(sub_start), str(sub_count)],
            check=True, capture_output=True, timeout=10,
        )
        subprocess.run(
            ["newgidmap", str(self._sentinel.pid),
             "0", str(outer_gid), "1",
             "1", str(sub_start), str(sub_count)],
            check=True, capture_output=True, timeout=10,
        )

        self._pid = self._sentinel.pid
        self._userns_path = f"/proc/{self._pid}/ns/user"

        # Register atexit cleanup.
        import atexit
        atexit.register(self.destroy)

        logger.debug("Storage userns sentinel started (pid=%d)", self._pid)

    @property
    def alive(self) -> bool:
        return self._sentinel is not None and self._sentinel.poll() is None

    @property
    def pid(self) -> int:
        assert self._pid is not None
        return self._pid

    def run(self, cmd: list[str], *, timeout: int = 300) -> subprocess.CompletedProcess:
        """Run a command inside the storage userns via nsenter."""
        return subprocess.run(
            ["nsenter", f"--user={self._userns_path}", "--"] + cmd,
            capture_output=True, text=True, timeout=timeout,
        )

    def rmtree(self, path: str | Path) -> None:
        """rm -rf inside the storage userns.

        Matches Podman's EnsureRemoveAll (system/rm.go) retry logic:
        1. Try rm -rf
        2. On failure: try recursive unmount, then retry rm -rf
        3. Retry loop for EBUSY (stale mount points)
        """
        path_s = str(path)
        result = self.run(["rm", "-rf", path_s])
        if result.returncode == 0:
            return

        # Podman: mount.RecursiveUnmount(dir)
        # Try to unmount anything beneath this dir.
        self.run(["umount", "-R", path_s])

        for attempt in range(50):
            result = self.run(["rm", "-rf", path_s])
            if result.returncode == 0:
                return
            # Check if the error is EBUSY-like (mount point)
            stderr = result.stderr or ""
            if "Device or resource busy" in stderr:
                # Podman: mount.Unmount(pe.Path) then retry
                self.run(["umount", "-R", path_s])
                import time
                time.sleep(0.01)  # 10ms like Podman
                continue
            # Not EBUSY — don't retry
            break

    def destroy(self) -> None:
        if self._sentinel is not None and self._sentinel.poll() is None:
            self._sentinel.kill()
            try:
                self._sentinel.wait(timeout=5)
            except Exception:
                pass
        self._sentinel = None
        self._pid = None


# ====================================================================== #
#  Public API — rootfs preparation                                         #
# ====================================================================== #


def prepare_rootfs_layers_from_docker(
    image_name: str,
    cache_dir: Path,
    pull: bool = True,
) -> list[Path]:
    """Extract Docker image as individual cached layers for overlayfs stacking.

    Uses ``docker save`` to get image layers, caches each by its content
    hash (diff_id).  Images sharing base layers skip re-extraction.

    Args:
        image_name: Docker image (e.g. ``"ubuntu:22.04"``).
        cache_dir: Root cache directory (e.g. ``~/.cache/nitrobox/rootfs``).
        pull: Pull the image first.

    Returns:
        Ordered list of layer directories (bottom to top) for overlayfs
        ``lowerdir`` stacking.

    Raises:
        RuntimeError: If layer extraction fails.
    """
    layers_dir = cache_dir / "layers"
    layers_dir.mkdir(parents=True, exist_ok=True)

    # Fast path: check manifest from a previous run to skip docker pull
    # entirely when all layers are already cached.
    diff_ids = _get_manifest_diff_ids(cache_dir, image_name)
    if diff_ids:
        layer_dirs = list(dict.fromkeys(
            layers_dir / _safe_cache_key(did) for did in diff_ids
        ))
        if all(d.exists() for d in layer_dirs):
            logger.info("All %d layers cached for %s", len(layer_dirs), image_name)
            return layer_dirs

    # Get diff_ids: manifest cache → ImageStore → registry → Docker API
    if not diff_ids:
        diff_ids = _get_image_diff_ids(image_name)

    # Check if all layers are already cached
    layer_dirs = list(dict.fromkeys(
        layers_dir / _safe_cache_key(did) for did in diff_ids
    ))
    # Get cached config from ImageStore (populated by _get_image_diff_ids)
    img_config = _image_store_get(image_name)

    if all(d.exists() for d in layer_dirs):
        logger.info("All %d layers cached for %s", len(layer_dirs), image_name)
        _write_manifest(cache_dir, image_name, diff_ids, image_config=img_config)
        return layer_dirs

    # Need to extract missing layers.  Iterate over the deduplicated
    # layer_dirs — NOT zip(diff_ids, layer_dirs) which misaligns when
    # the image has duplicate diff-ids.
    needed_keys = {d.name for d in layer_dirs if not d.exists()}
    # Map cache keys back to full diff_ids for the registry downloader.
    _key_to_did = {_safe_cache_key(did): did for did in diff_ids}
    needed = {_key_to_did[k] for k in needed_keys if k in _key_to_did}
    logger.info("Extracting layers for %s (%d layers, %d cached)",
                image_name, len(diff_ids), len(layer_dirs) - len(needed))

    # Primary: local Docker cache (docker save — pure local IO, fastest)
    # Fallback: registry download (network, slower)
    extracted = False
    try:
        if get_client().image_exists(image_name):
            resp = get_client().image_save(image_name)
            with tarfile.open(fileobj=resp, mode="r|") as outer_tar:
                _extract_layers_from_save_tar(outer_tar, diff_ids, layers_dir)
            extracted = True
    except Exception as e:
        logger.debug("Docker save failed for %s: %s", image_name, e)

    if not extracted:
        try:
            _extract_layers_from_registry(image_name, needed, layers_dir)
        except Exception as e:
            logger.debug("Registry extraction failed for %s: %s", image_name, e)
            # Last resort: pull via Docker then save
            try:
                if pull:
                    _pull_or_check_local(image_name)
                resp = get_client().image_save(image_name)
                with tarfile.open(fileobj=resp, mode="r|") as outer_tar:
                    _extract_layers_from_save_tar(outer_tar, diff_ids, layers_dir)
            except Exception:
                raise RuntimeError(
                    f"Cannot extract layers for {image_name!r} from "
                    f"Docker or registry."
                ) from e

    # Verify ALL layers were extracted before writing the manifest.
    still_missing = [d for d in layer_dirs if not d.exists()]
    if still_missing:
        names = [d.name for d in still_missing[:3]]
        raise RuntimeError(
            f"Layer extraction incomplete for {image_name!r}: "
            f"{len(still_missing)} layer(s) missing ({', '.join(names)})"
        )

    _write_manifest(cache_dir, image_name, diff_ids, image_config=img_config)
    # Deduplicate layers preserving order (overlayfs ELOOP on duplicate lowerdir).
    seen: set[Path] = set()
    unique_dirs: list[Path] = []
    for d in layer_dirs:
        if d not in seen:
            seen.add(d)
            unique_dirs.append(d)
    if len(unique_dirs) < len(layer_dirs):
        logger.debug("Deduplicated %d → %d layers", len(layer_dirs), len(unique_dirs))
    logger.info("Layer cache ready for %s: %d layers", image_name, len(unique_dirs))
    return unique_dirs


# ======================================================================
#  Internal — layer extraction & cache management                          #
# ====================================================================== #


def _extract_layers_from_registry(
    image_name: str,
    needed_diff_ids: set[str],
    layers_dir: Path,
) -> None:
    """Download and extract layers directly from registry (no Docker/Podman).

    Uses streaming download (one layer at a time) to avoid loading
    all layers into memory simultaneously.
    """
    import gzip
    from nitrobox.image.registry import iter_image_layers

    for diff_id, tmp_path in iter_image_layers(image_name, needed_diff_ids):
        try:
            layer_dir = layers_dir / _safe_cache_key(diff_id)
            if layer_dir.exists():
                continue
            # Registry layers are gzip-compressed tarballs
            compressed_blob = tmp_path.read_bytes()
            try:
                raw = gzip.decompress(compressed_blob)
            except gzip.BadGzipFile:
                raw = compressed_blob  # already uncompressed
            del compressed_blob
            _extract_single_layer_locked(raw, layer_dir, layers_dir)
            del raw
        finally:
            tmp_path.unlink(missing_ok=True)


def _extract_layers_from_save_tar(
    outer_tar: tarfile.TarFile,
    diff_ids: list[str],
    layers_dir: Path,
) -> None:
    """Parse docker save tar and extract layer tarballs into cache dirs.

    Handles both legacy Docker format (hash/layer.tar) and modern
    Docker/OCI hybrid format (blobs/sha256/<hash>).
    """
    # Read all members into memory.  Docker save tarballs are typically
    # small (just metadata + compressed layers), so this is fine.
    manifest_data = None
    blobs: dict[str, bytes] = {}

    for member in outer_tar:
        f = outer_tar.extractfile(member)
        if f is None:
            continue
        data = f.read()
        f.close()

        if member.name == "manifest.json":
            manifest_data = json.loads(data)
        else:
            blobs[member.name] = data

    if not manifest_data:
        raise RuntimeError("Cannot parse docker save output: no manifest.json found")

    # manifest.json = [{"Layers": ["blobs/sha256/<hash>", ...], ...}]
    layer_paths = manifest_data[0].get("Layers", [])
    if len(layer_paths) != len(diff_ids):
        raise ValueError(
            f"Layer count mismatch: manifest has {len(layer_paths)}, "
            f"diff_ids has {len(diff_ids)}"
        )

    for layer_path, diff_id in zip(layer_paths, diff_ids):
        cache_key = _safe_cache_key(diff_id)
        layer_dir = layers_dir / cache_key
        if layer_dir.exists():
            continue  # Already cached

        raw = blobs.get(layer_path)
        if raw is None:
            raise RuntimeError(f"Layer blob not found in archive: {layer_path}")

        _extract_single_layer_locked(raw, layer_dir, layers_dir)


def rmtree_mapped(path: str | Path) -> None:
    """Remove a directory that may contain files with mapped UIDs.

    Matches Podman's ``EnsureRemoveAll`` (system/rm.go):

    1. Try ``shutil.rmtree`` (fast path — works if rootful or no mapped
       UIDs).
    2. On ``PermissionError``: enter the persistent storage userns and
       ``rm -rf`` with EBUSY retry + unmount logic.
    3. Last resort: best-effort ``shutil.rmtree(ignore_errors=True)``.
    """
    import shutil

    path = Path(path)
    if not path.exists():
        return

    # Podman: first attempt os.RemoveAll() — fast path
    try:
        shutil.rmtree(path)
        return
    except PermissionError:
        pass
    except OSError as e:
        import errno as errno_mod
        if e.errno != errno_mod.EBUSY:
            pass  # fall through to userns path
        # EBUSY: try unmount first, then userns path
        import subprocess
        subprocess.run(
            ["umount", "-R", str(path)],
            capture_output=True, timeout=30,
        )
        try:
            shutil.rmtree(path)
            return
        except OSError:
            pass

    # Enter the persistent storage userns to delete.
    ns = _StorageNS.get()
    if ns is not None:
        ns.rmtree(path)
        return

    # Last resort: best-effort.
    shutil.rmtree(path, ignore_errors=True)


# Keep old name for internal callers
_rmtree_mapped = rmtree_mapped


def _extract_single_layer_locked(
    raw: bytes,
    layer_dir: Path,
    layers_dir: Path,
) -> None:
    """Extract a single layer tarball with file locking for concurrent safety."""
    import threading
    tid = threading.current_thread().name
    lock_path = layers_dir / f".{layer_dir.name}.lock"
    tmp_dir = layer_dir.with_suffix(".extracting")
    import threading, sys
    tid = threading.current_thread().name
    print(f"[{tid}] LOCK {layer_dir.name[:16]}... blob={len(raw)}", file=sys.stderr, flush=True)
    with open(lock_path, "w") as lock_fd:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        try:
            if layer_dir.exists():
                print(f"[{tid}] SKIP {layer_dir.name[:16]}... (cached)", file=sys.stderr, flush=True)
                return

            print(f"[{tid}] EXTRACT {layer_dir.name[:16]}... ({len(raw)} bytes)", file=sys.stderr, flush=True)
            if tmp_dir.exists():
                _rmtree_mapped(tmp_dir)
            tmp_dir.mkdir(parents=True)

            if os.geteuid() != 0:
                _extract_tar_in_userns(raw, tmp_dir)
            else:
                with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as lt:
                    lt.extractall(tmp_dir, filter="tar")
                from nitrobox.storage.whiteout import _convert_whiteouts_in_layer
                _convert_whiteouts_in_layer(tmp_dir)

            tmp_dir.rename(layer_dir)
            n_files = sum(1 for _ in layer_dir.rglob("*") if _.is_file())
            print(f"[{tid}] DONE {layer_dir.name[:16]}... ({n_files} files)", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"[{tid}] FAIL {layer_dir.name[:16]}... {e}", file=sys.stderr, flush=True)
            if tmp_dir.exists():
                _rmtree_mapped(tmp_dir)
            raise
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
    # Clean up lock file (best effort)
    try:
        lock_path.unlink()
    except OSError:
        pass


def _extract_tar_in_userns(raw: bytes, dest_dir: Path) -> None:
    """Extract a layer tar inside a user namespace to preserve file ownership.

    Mirrors Podman's rootless ``applyDiff``: creates a temporary user
    namespace with full UID/GID mapping, then runs ``tar xf`` inside it.
    The kernel remaps container UIDs to host UIDs automatically via the
    mapping — equivalent to Podman's ``remapIDs()`` + ``lchown()``.

    Without this, ``tarfile.extractall()`` as a regular user forces all
    files to the extractor's UID — breaking services like Postfix that
    check spool directory ownership.

    Falls back to plain ``tarfile.extractall()`` when no subuid range
    is available (single-UID mode).
    """
    from nitrobox.config import detect_subuid_range

    subuid_range = detect_subuid_range()
    if not subuid_range:
        # No subuid range — fall back to basic extraction (single-UID mode)
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as lt:
            lt.extractall(dest_dir, filter="tar")
        return

    outer_uid, sub_start, sub_count = subuid_range
    outer_gid = os.getgid()

    # Write tar to temp file (Rust side passes path to `tar xf`).
    tar_path = dest_dir.parent / f".{dest_dir.name}.layer.tar"
    tar_path.write_bytes(raw)

    try:
        from nitrobox._core import py_extract_tar_in_userns

        py_extract_tar_in_userns(
            str(tar_path), str(dest_dir),
            outer_uid, outer_gid, sub_start, sub_count,
        )
    finally:
        tar_path.unlink(missing_ok=True)


def _pull_or_check_local(image_name: str, **_kwargs: object) -> None:
    """Ensure image is available locally, pulling only if needed."""
    client = get_client()
    if client.image_exists(image_name):
        logger.debug("Image exists locally: %s", image_name)
        return

    logger.info("Pulling image: %s", image_name)
    client.image_pull(image_name)


def prepare_rootfs_from_docker(
    image_name: str,
    output_dir: str | Path,
    pull: bool = True,
) -> Path:
    """Export a Docker image as a rootfs directory.

    Equivalent to::

        docker pull <image_name>
        docker export $(docker create <image_name>) | tar -C <output_dir> -xf -

    Args:
        image_name: Docker image (e.g. ``"ubuntu:22.04"``).
        output_dir: Target directory for the extracted rootfs.
        pull: Pull the image first (set ``False`` if already local).

    Returns:
        Path to *output_dir*.

    Raises:
        RuntimeError: If any Docker/tar command fails.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    client = get_client()
    if pull:
        _pull_or_check_local(image_name)

    logger.info("Creating temporary container from %s", image_name)
    container_id = client.container_create(image_name)

    try:
        logger.info("Exporting %s -> %s", image_name, output_dir)
        resp = client.container_export(container_id)
        with tarfile.open(fileobj=resp, mode="r|") as tar:
            tar.extractall(output_dir, filter="tar")
    finally:
        client.container_remove(container_id, force=True)

    try:
        client.image_remove(image_name, force=True)
    except Exception:
        pass

    logger.info("Rootfs ready: %s", output_dir)
    return output_dir



def prepare_btrfs_rootfs_from_docker(
    image_name: str,
    subvolume_path: str | Path,
    pull: bool = True,
) -> Path:
    """Export a Docker image into a btrfs subvolume for snapshot-based sandboxes.

    The target path must be on a btrfs-formatted filesystem.
    """
    import shutil as _shutil

    if _shutil.which("btrfs") is None:
        raise FileNotFoundError(
            "btrfs-progs not found. Install: apt-get install btrfs-progs"
        )

    subvolume_path = Path(subvolume_path)

    if subvolume_path.exists():
        check = subprocess.run(
            ["btrfs", "subvolume", "show", str(subvolume_path)],
            capture_output=True,
            text=True,
        )
        if check.returncode == 0:
            logger.info("Deleting existing btrfs subvolume: %s", subvolume_path)
            subprocess.run(
                ["btrfs", "subvolume", "delete", str(subvolume_path)],
                capture_output=True,
            )
        else:
            _shutil.rmtree(subvolume_path)

    subvolume_path.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["btrfs", "subvolume", "create", str(subvolume_path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"btrfs subvolume create failed: {result.stderr.strip()}. "
            f"Ensure {subvolume_path.parent} is on a btrfs filesystem."
        )
    logger.info("Created btrfs subvolume: %s", subvolume_path)

    client = get_client()
    if pull:
        _pull_or_check_local(image_name)

    logger.info("Creating temporary container from %s", image_name)
    container_id = client.container_create(image_name)

    try:
        logger.info(
            "Exporting %s -> %s (btrfs subvolume)", image_name, subvolume_path
        )
        resp = client.container_export(container_id)
        with tarfile.open(fileobj=resp, mode="r|") as tar:
            tar.extractall(subvolume_path, filter="tar")
    finally:
        client.container_remove(container_id, force=True)

    try:
        client.image_remove(image_name, force=True)
    except Exception:
        pass

    logger.info("btrfs rootfs ready: %s", subvolume_path)
    return subvolume_path


# ====================================================================== #
#  Image resolution helpers (moved from Sandbox)                           #
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

    if fs_backend == "btrfs":
        return resolve_btrfs_rootfs(image, rootfs_cache_dir), None

    # --- overlayfs: layer-level caching ---
    t0 = time.monotonic()
    layer_dirs = prepare_rootfs_layers_from_docker(
        image, rootfs_cache_dir, pull=True,
    )
    elapsed_ms = (time.monotonic() - t0) * 1000
    logger.info(
        "Layer cache ready (%.1fms): %s (%d layers)",
        elapsed_ms, image, len(layer_dirs),
    )
    return layer_dirs[0], layer_dirs


def _get_image_digest(image: str) -> str | None:
    """Get the content digest (sha256) of a Docker image.

    Returns the digest string (e.g. ``sha256_abc123...``) or None
    if the image doesn't exist or Docker is unavailable.
    """
    try:
        from nitrobox.image.docker import get_client, ImageNotFoundError
        info = get_client().image_inspect(image)
        digest = info.get("Id", "")
        return digest.replace(":", "_")[:80] if digest else None
    except ImageNotFoundError:
        return None
    except Exception:
        return None


def _resolve_cached_rootfs(
    image: str,
    rootfs_cache_dir: Path,
    prepare_fn: Any,
    *,
    verify_fn: Any = None,
    label: str = "rootfs",
) -> Path:
    """Resolve a flat rootfs with file-lock-based caching.

    Uses the image's content digest as the cache key so that
    images with different tags but identical content share the
    same cached rootfs (like Docker's layer cache).

    Shared logic for btrfs and docker-export rootfs preparation.
    """
    candidate = Path(image)
    if candidate.exists() and candidate.is_dir():
        if verify_fn:
            verify_fn(candidate)
        return candidate

    # Use content digest as cache key when available, falling
    # back to the image name.  This ensures images with different
    # tags but identical content (e.g. different compose project
    # names) share the same cached rootfs.
    digest = _get_image_digest(image)
    cache_key = digest if digest else image.replace("/", "_").replace(":", "_").replace(".", "_")
    cached_rootfs = rootfs_cache_dir / cache_key

    # Also check under the name-based key for backward compat
    name_key = image.replace("/", "_").replace(":", "_").replace(".", "_")
    name_cached = rootfs_cache_dir / name_key
    if not cached_rootfs.exists() and name_cached.exists() and name_cached.is_dir():
        cached_rootfs = name_cached

    if cached_rootfs.exists() and cached_rootfs.is_dir():
        if verify_fn:
            verify_fn(cached_rootfs)
        return cached_rootfs

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
            logger.info(
                "Auto-prepared %s (%.1fms): %s -> %s",
                label, elapsed_ms, image, cached_rootfs,
            )
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
    return cached_rootfs


def resolve_btrfs_rootfs(image: str, rootfs_cache_dir: Path) -> Path:
    """Resolve flat rootfs for btrfs backend."""
    from nitrobox.sandbox import Sandbox
    return _resolve_cached_rootfs(
        image, rootfs_cache_dir, prepare_btrfs_rootfs_from_docker,
        verify_fn=Sandbox._verify_btrfs_subvolume,
        label="btrfs rootfs",
    )


def resolve_flat_rootfs(image: str, rootfs_cache_dir: Path) -> Path:
    """Resolve flat rootfs via docker export (for userns/rootless)."""
    return _resolve_cached_rootfs(
        image, rootfs_cache_dir, prepare_rootfs_from_docker,
        label="flat rootfs",
    )
