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


def _containers_storage_root() -> Path | None:
    """Return the containers/storage graph root, or None if not configured."""
    # Check env var first, then default rootless path
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

    Reads the store's JSON metadata files directly — no Go binary needed
    for the read path. Returns None if the image isn't in the store.
    """
    graph_root = _containers_storage_root()
    if graph_root is None:
        return None

    try:
        # containers/storage stores images/layers JSON in:
        #   {graphRoot}/{driver}-images/images.json
        #   {graphRoot}/{driver}-layers/layers.json
        # Detect the driver from what directories exist
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
            lid = layer["id"]
            layer_parent[lid] = layer.get("parent", "")

        # Find the image by name
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

        # Walk layer chain top→bottom
        chain: list[str] = []
        lid = top_layer
        while lid:
            chain.append(lid)
            lid = layer_parent.get(lid, "")

        # Build paths (bottom-to-top for overlayfs lowerdir)
        chain.reverse()
        paths: list[Path] = []
        for lid in chain:
            if driver == "vfs":
                p = graph_root / "vfs" / "dir" / lid
            else:
                p = graph_root / driver / lid / "diff"
            if not p.is_dir():
                return None  # Layer directory missing
            paths.append(p)

        logger.info("containers/storage: %s has %d layers (zero-copy)", image_name, len(paths))
        return paths

    except Exception as e:
        logger.debug("containers/storage read failed: %s", e)
        return None


def _containers_storage_pull(image_name: str) -> bool:
    """Pull an image into containers/storage via nitrobox-core image-pull.

    Requires userns with full UID mapping. Returns True on success.
    """
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
    userns_r, userns_w = os.pipe()
    go_r, go_w = os.pipe()
    json_r, json_w = os.pipe()

    pid = os.fork()
    if pid == 0:
        os.close(userns_r)
        os.close(go_w)
        os.close(json_w)
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        if libc.unshare(0x10000000) != 0:
            os._exit(1)
        os.write(userns_w, b"R")
        os.close(userns_w)
        os.read(go_r, 1)
        os.close(go_r)
        os.dup2(json_r, 0)
        os.close(json_r)
        os.execvp(bin_path, [bin_path, "image-pull"])
        os._exit(127)

    os.close(userns_w)
    os.close(go_r)
    os.close(json_r)
    os.read(userns_r, 1)
    os.close(userns_r)

    pid_s = str(pid)
    subprocess.run(
        ["newuidmap", pid_s, "0", str(outer_uid), "1", "1", str(sub_start), str(sub_count)],
        check=False, capture_output=True,
    )
    subprocess.run(
        ["newgidmap", pid_s, "0", str(outer_gid), "1", "1", str(sub_start), str(sub_count)],
        check=False, capture_output=True,
    )

    os.write(go_w, b"G")
    os.close(go_w)
    os.write(json_w, req)
    os.close(json_w)

    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status) == 0


def prepare_rootfs_layers_from_docker(
    image_name: str,
    cache_dir: Path,
    pull: bool = True,
) -> list[Path]:
    """Get image layers as directories for overlayfs stacking.

    Uses containers/storage for zero-copy layer access:
      1. Check if image exists in store → return diff paths directly
      2. Pull from registry into store → return diff paths

    No Docker daemon needed. Layers are user-owned and can be used
    directly as overlayfs lowerdir.

    Args:
        image_name: Image reference (e.g. ``"ubuntu:22.04"``).
        cache_dir: Unused (kept for API compatibility). Layers live
            in the containers/storage graph root.
        pull: If True, pull from registry when image not in store.

    Returns:
        Ordered list of layer directories (bottom to top).
    """
    # 1. Check containers/storage
    layers = _try_containers_storage(image_name)
    if layers is not None:
        logger.info("Layer cache ready for %s: %d layers (zero-copy)", image_name, len(layers))
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
            logger.info("Layer cache ready for %s: %d layers (zero-copy)", image_name, len(layers))
            return layers

    raise RuntimeError(f"Image {image_name!r} not found in containers/storage.")


# ======================================================================
#  Layer locking — flock-based reference counting                          #
# ======================================================================
#
# Layers are shared across sandboxes.  Two problems arise without locking:
#   1. Concurrent docker save: multiple threads extract the same layer
#   2. Delete while in use: rmtree removes a layer dir while another
#      sandbox's overlayfs is using it as lowerdir
#
# Solution: flock on per-layer lock files.
#   - Extraction: LOCK_EX (already in _extract_single_layer_locked)
#   - Usage:      LOCK_SH held for sandbox lifetime (acquire_layer_locks)
#   - Deletion:   LOCK_EX blocks until all LOCK_SH released (remove_layer_locked)


def acquire_layer_locks(layer_dirs: list[Path]) -> list[int]:
    """Acquire shared locks on layer directories.

    Returns a list of lock file descriptors that must be kept open
    (and passed to :func:`release_layer_locks`) for the sandbox lifetime.
    While held, :func:`remove_layer_locked` will block.
    """
    fds: list[int] = []
    for layer_dir in layer_dirs:
        lock_path = layer_dir.parent / f".{layer_dir.name}.lock"
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError:
            # If non-blocking fails (shouldn't for SH), fall back to blocking
            fcntl.flock(fd, fcntl.LOCK_SH)
        fds.append(fd)
    return fds


def release_layer_locks(lock_fds: list[int]) -> None:
    """Release shared locks acquired by :func:`acquire_layer_locks`."""
    for fd in lock_fds:
        try:
            os.close(fd)  # closing the fd releases the flock
        except OSError:
            pass


def remove_layer_locked(layer_dir: Path) -> None:
    """Remove a layer directory if no sandbox is using it.

    Tries LOCK_EX non-blocking.  If another sandbox holds LOCK_SH
    (layer in use as overlayfs lowerdir), skips removal — the layer
    will be cleaned up when the last sandbox releases it, or on a
    subsequent ``down --rmi`` call.
    """
    lock_path = layer_dir.parent / f".{layer_dir.name}.lock"
    if not layer_dir.exists():
        return
    try:
        with open(lock_path, "w") as lock_fd:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                logger.debug("Layer %s in use, skipping removal", layer_dir.name)
                return
            try:
                rmtree_mapped(layer_dir)
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_path.unlink(missing_ok=True)
    except OSError as e:
        logger.debug("remove_layer_locked %s: %s", layer_dir, e)


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
    lock_path = layers_dir / f".{layer_dir.name}.lock"
    tmp_dir = layer_dir.with_suffix(".extracting")
    with open(lock_path, "w") as lock_fd:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        try:
            if layer_dir.exists():
                return

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
        except Exception:
            if tmp_dir.exists():
                _rmtree_mapped(tmp_dir)
            raise
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
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
        from nitrobox._backend import py_extract_tar_in_userns

        py_extract_tar_in_userns(
            str(tar_path), str(dest_dir),
            outer_uid, outer_gid, sub_start, sub_count,
        )
    finally:
        tar_path.unlink(missing_ok=True)


# ======================================================================
#  Snapshot-based extraction (zero-decompress fast path)                  #
# ======================================================================
#
# When Docker (with containerd snapshotter) already has an image pulled,
# its layers are stored as pre-extracted directories under:
#   /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/{id}/fs/
#
# These directories are root-owned and inaccessible directly, but we can
# reach them via Docker bind-mounts.  This skips the entire
# docker-save → gzip-decompress → tar-extract pipeline (~7x faster).
#
# Flow:
#   1. docker create + start <image> → parse /proc/{pid}/mountinfo
#      to discover snapshot paths for each layer
#   2. docker create a "proxy" alpine container that bind-mounts every
#      snapshot dir
#   3. docker exec proxy tar c -C /l{i} .  →  pipe to userns extractor
#      (parallel, one thread per layer)
#   4. Clean up both containers


def _discover_snapshot_paths(image_name: str) -> list[str] | None:
    """Start a temporary container to discover containerd snapshot paths.

    Returns an ordered list of snapshot ``fs/`` paths (bottom-to-top,
    matching diff_id order), or *None* if discovery fails.
    """
    import re

    client = get_client()
    cid = None
    try:
        cid = client.container_create(image_name, command=["sleep", "30"])
        client.container_start(cid)
        info = client.container_inspect(cid)
        pid = info.get("State", {}).get("Pid")
        if not pid:
            return None

        # Parse overlay lowerdir from mountinfo
        mountinfo = Path(f"/proc/{pid}/mountinfo").read_text()
        lowerdirs: list[str] = []
        for line in mountinfo.splitlines():
            if "overlay" in line and "lowerdir=" in line:
                m = re.search(r"lowerdir=([^ ,]+)", line)
                if m:
                    lowerdirs = m.group(1).split(":")
                break

        if not lowerdirs:
            return None

        return lowerdirs
    except Exception as exc:
        logger.debug("Snapshot discovery failed for %s: %s", image_name, exc)
        return None
    finally:
        if cid:
            # Force-remove (skip graceful stop — saves ~1s).
            try:
                client.container_remove(cid, force=True)
            except Exception:
                pass


def _map_snapshots_to_diff_ids(
    lowerdirs: list[str],
    diff_ids: list[str],
) -> list[tuple[str, str]] | None:
    """Map containerd snapshot lowerdir paths to image diff_ids.

    The overlay lowerdir list is top-to-bottom (newest first).
    Docker adds init layers at the top (typically 3).  We skip those,
    reverse the remaining, and zip with diff_ids (which are bottom-to-top).

    Returns list of ``(diff_id, snapshot_path)`` pairs, or None on mismatch.
    """
    n_image = len(diff_ids)
    n_extra = len(lowerdirs) - n_image
    if n_extra < 0:
        logger.debug(
            "Fewer lowerdirs (%d) than diff_ids (%d) — cannot map",
            len(lowerdirs), n_image,
        )
        return None

    # Image layers are the bottom N entries of the lowerdir list.
    # Reverse them to get bottom-to-top order matching diff_ids.
    image_lowerdirs = list(reversed(lowerdirs[n_extra:]))
    return list(zip(diff_ids, image_lowerdirs))


def _extract_layers_from_snapshots(
    image_name: str,
    diff_ids: list[str],
    layers_dir: Path,
) -> bool:
    """Extract uncached layers directly from containerd snapshots.

    Returns True if all layers were extracted successfully.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    t0 = time.monotonic()
    lowerdirs = _discover_snapshot_paths(image_name)
    if not lowerdirs:
        return False

    mapping = _map_snapshots_to_diff_ids(lowerdirs, diff_ids)
    if not mapping:
        return False

    # Identify which layers still need extraction.
    needed: list[tuple[str, str]] = []  # (diff_id, snapshot_path)
    for diff_id, snap_path in mapping:
        layer_dir = layers_dir / _safe_cache_key(diff_id)
        if not layer_dir.exists():
            needed.append((diff_id, snap_path))

    if not needed:
        logger.info("Snapshot fast-path: all %d layers cached", len(diff_ids))
        return True

    t_discover = time.monotonic() - t0
    logger.info(
        "Snapshot fast-path: %d/%d layers to extract (discovery %.1fs)",
        len(needed), len(diff_ids), t_discover,
    )

    # Create proxy container that bind-mounts every needed snapshot dir.
    client = get_client()
    binds: list[str] = []
    idx_map: dict[str, int] = {}  # diff_id → mount index
    for i, (diff_id, snap_path) in enumerate(needed):
        binds.append(f"{snap_path}:/l{i}:ro")
        idx_map[diff_id] = i

    proxy_cid = None
    try:
        proxy_cid = client.container_create(
            "alpine:latest",
            command=["sleep", "3600"],
            binds=binds,
        )
        client.container_start(proxy_cid)

        # Give the container a moment to be ready for exec.
        # (In practice, sleep is ready instantly, but be safe.)
        time.sleep(0.1)

        def _extract_one(diff_id: str) -> tuple[str, float]:
            idx = idx_map[diff_id]
            layer_dir = layers_dir / _safe_cache_key(diff_id)
            tmp_dir = layer_dir.with_suffix(".extracting")

            if layer_dir.exists():
                return diff_id, 0.0

            if tmp_dir.exists():
                _rmtree_mapped(tmp_dir)
            tmp_dir.mkdir(parents=True)

            t_start = time.monotonic()
            try:
                _extract_snapshot_layer(proxy_cid, idx, tmp_dir)
                tmp_dir.rename(layer_dir)
            except Exception:
                if tmp_dir.exists():
                    _rmtree_mapped(tmp_dir)
                raise
            return diff_id, time.monotonic() - t_start

        errors: list[str] = []
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {
                pool.submit(_extract_one, did): did
                for did, _ in needed
            }
            for future in as_completed(futures):
                did = futures[future]
                try:
                    _, elapsed = future.result()
                    cache_key = _safe_cache_key(did)[:16]
                    if elapsed > 0:
                        logger.debug(
                            "Snapshot extract %s: %.1fs", cache_key, elapsed,
                        )
                except Exception as exc:
                    errors.append(f"{did[:16]}: {exc}")
                    logger.debug("Snapshot extract failed %s: %s", did[:16], exc)

        if errors:
            logger.warning(
                "Snapshot extraction had %d errors, falling back", len(errors),
            )
            return False

        total = time.monotonic() - t0
        logger.info(
            "Snapshot fast-path complete: %d layers in %.1fs", len(needed), total,
        )
        return True

    except Exception as exc:
        logger.debug("Snapshot proxy failed: %s", exc)
        return False
    finally:
        if proxy_cid:
            try:
                client.container_remove(proxy_cid, force=True)
            except Exception:
                pass


def _extract_snapshot_layer(
    proxy_cid: str,
    mount_idx: int,
    dest_dir: Path,
) -> None:
    """Extract a single snapshot layer via ``docker exec tar`` into *dest_dir*.

    The proxy container has the snapshot mounted at ``/l{mount_idx}``.
    Uses a named FIFO to pipe ``docker exec tar`` directly into the Rust
    userns extractor — no temp file, no memory buffering.
    """
    import threading
    from nitrobox.config import detect_subuid_range

    subuid_range = detect_subuid_range()
    fifo_path = dest_dir.parent / f".{dest_dir.name}.snap.fifo"
    use_fifo = bool(subuid_range) and os.geteuid() != 0

    if use_fifo:
        try:
            fifo_path.unlink(missing_ok=True)
            os.mkfifo(fifo_path)
        except OSError:
            use_fifo = False

    if use_fifo:
        outer_uid, sub_start, sub_count = subuid_range  # type: ignore[misc]
        outer_gid = os.getgid()

        # Writer thread: open(fifo, "wb") blocks until the Rust extractor
        # (forked child) opens the read end.  Must be in a separate thread
        # so the main thread can call py_extract_tar_in_userns.
        writer_exc: list[BaseException | None] = [None]

        def _writer() -> None:
            try:
                with open(fifo_path, "wb") as wf:
                    proc = subprocess.run(
                        ["docker", "exec", proxy_cid,
                         "tar", "c", "-C", f"/l{mount_idx}", "."],
                        stdout=wf, stderr=subprocess.PIPE, timeout=300,
                    )
                if proc.returncode != 0:
                    writer_exc[0] = RuntimeError(
                        f"docker exec tar rc={proc.returncode}: "
                        f"{proc.stderr.decode(errors='replace')[:200]}"
                    )
            except Exception as exc:
                writer_exc[0] = exc

        wt = threading.Thread(target=_writer, daemon=True)
        wt.start()
        try:
            from nitrobox._backend import py_extract_tar_in_userns
            py_extract_tar_in_userns(
                str(fifo_path), str(dest_dir),
                outer_uid, outer_gid, sub_start, sub_count,
            )
        finally:
            wt.join(timeout=60)
            fifo_path.unlink(missing_ok=True)

        if writer_exc[0] is not None:
            raise writer_exc[0]
    else:
        # Fallback: temp file (rootful or no userns).
        tar_path = dest_dir.parent / f".{dest_dir.name}.snap.tar"
        try:
            with open(tar_path, "wb") as f:
                proc = subprocess.run(
                    ["docker", "exec", proxy_cid,
                     "tar", "c", "-C", f"/l{mount_idx}", "."],
                    stdout=f, stderr=subprocess.PIPE, timeout=300,
                )
            if proc.returncode != 0:
                raise RuntimeError(
                    f"docker exec tar failed (rc={proc.returncode}): "
                    f"{proc.stderr.decode(errors='replace')[:200]}"
                )
            with tarfile.open(str(tar_path), mode="r:") as lt:
                lt.extractall(dest_dir, filter="tar")
            if os.geteuid() == 0:
                from nitrobox.storage.whiteout import _convert_whiteouts_in_layer
                _convert_whiteouts_in_layer(dest_dir)
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
