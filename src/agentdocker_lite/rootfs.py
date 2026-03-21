"""Utilities for preparing base rootfs directories from Docker images."""

from __future__ import annotations

import fcntl
import io
import json
import logging
import os
import subprocess
import tarfile
from pathlib import Path

logger = logging.getLogger(__name__)


# ====================================================================== #
#  Docker layer-level caching                                              #
# ====================================================================== #


def _safe_cache_key(diff_id: str) -> str:
    """Convert a diff_id like 'sha256:abc...' to a short filesystem-safe key.

    Uses first 16 hex chars of the hash for brevity.  The new mount API
    (``fsconfig``) has a ~256-byte limit per lowerdir parameter, so full
    64-char SHA256 hashes cause mount failures with many layers.
    16 hex chars = 64 bits of collision resistance — sufficient for a
    local per-user cache.
    """
    # "sha256:abcdef..." → "abcdef..."[:16]
    _, _, hexpart = diff_id.partition(":")
    return hexpart[:16] if hexpart else diff_id.replace(":", "_")[:16]


def _detect_whiteout_strategy() -> str:
    """Detect the best whiteout conversion strategy for this environment.

    Returns:
        ``"root"``  — real root: mknod(0,0) + trusted.overlay.* (any kernel)
        ``"xattr"`` — kernel >= 6.7: user.overlay.whiteout xattr, no mknod
        ``"userns"`` — kernel >= 5.11: mknod(0,0) inside unshare --user
        ``"none"``  — unsupported: layer caching unavailable
    """
    if os.geteuid() == 0:
        return "root"

    major, minor = _kernel_version()

    if (major, minor) >= (6, 7):
        return "xattr"
    if (major, minor) >= (5, 11):
        return "userns"
    return "none"


def _kernel_version() -> tuple[int, int]:
    """Return (major, minor) kernel version."""
    release = os.uname().release  # e.g. "6.19.8-1-cachyos"
    parts = release.split(".")
    try:
        return int(parts[0]), int(parts[1])
    except (IndexError, ValueError):
        return 0, 0


def _convert_whiteouts_in_layer(layer_dir: Path, strategy: str = "") -> None:
    """Convert OCI whiteout files to overlayfs-native whiteouts.

    OCI uses ``.wh.<name>`` sentinel files for deletions.
    The conversion strategy depends on the environment:

    - ``"root"``: mknod(0,0) + trusted.overlay.opaque (standard)
    - ``"xattr"``: user.overlay.whiteout xattr (kernel >= 6.7, no root)
    - ``"userns"``: mknod(0,0) inside unshare --user (kernel >= 5.11)
    """
    if not strategy:
        strategy = _detect_whiteout_strategy()

    if strategy == "userns":
        _convert_whiteouts_in_userns(layer_dir)
        return

    is_user = strategy == "xattr"
    xattr_prefix = "user.overlay" if is_user else "trusted.overlay"

    for dirpath, _dirnames, filenames in os.walk(layer_dir):
        dp = Path(dirpath)
        for fname in filenames:
            if not fname.startswith(".wh."):
                continue
            wh_path = dp / fname
            if fname == ".wh..wh..opq":
                wh_path.unlink()
                subprocess.run(
                    ["setfattr", "-n", f"{xattr_prefix}.opaque",
                     "-v", "x" if is_user else "y", str(dp)],
                    capture_output=True,
                )
            else:
                target_name = fname[4:]  # strip ".wh." prefix
                target_path = dp / target_name
                wh_path.unlink()
                if is_user:
                    # xattr-based whiteout: regular file + user.overlay.whiteout
                    target_path.touch()
                    subprocess.run(
                        ["setfattr", "-n", f"{xattr_prefix}.whiteout",
                         "-v", "y", str(target_path)],
                        capture_output=True,
                    )
                else:
                    # char device (0,0) whiteout
                    os.mknod(str(target_path), 0o600 | 0o020000, os.makedev(0, 0))


def _convert_whiteouts_in_userns(layer_dir: Path) -> None:
    """Convert whiteouts by running mknod inside a user namespace.

    Kernel >= 5.11: fake CAP_MKNOD in userns allows creating (0,0) device.
    Uses user.overlay.opaque for opaque dirs (userns can't set trusted.*).
    """
    # Build a small script that does the conversion inside a userns
    script = (
        "import os, subprocess, sys\n"
        "from pathlib import Path\n"
        "layer_dir = Path(sys.argv[1])\n"
        "for dirpath, _dns, fnames in os.walk(layer_dir):\n"
        "    dp = Path(dirpath)\n"
        "    for fname in fnames:\n"
        "        if not fname.startswith('.wh.'): continue\n"
        "        wh = dp / fname\n"
        "        if fname == '.wh..wh..opq':\n"
        "            wh.unlink()\n"
        "            subprocess.run(['setfattr','-n','user.overlay.opaque','-v','y',str(dp)],capture_output=True)\n"
        "        else:\n"
        "            target = dp / fname[4:]\n"
        "            wh.unlink()\n"
        "            os.mknod(str(target), 0o600|0o020000, os.makedev(0,0))\n"
    )
    result = subprocess.run(
        ["unshare", "--user", "--map-root-user",
         "python3", "-c", script, str(layer_dir)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        logger.warning("userns whiteout conversion failed: %s", result.stderr.strip())



def _get_image_diff_ids(image_name: str) -> list[str] | None:
    """Get layer diff_ids from docker inspect."""
    result = subprocess.run(
        ["docker", "inspect", "--format",
         "{{json .RootFS.Layers}}", image_name],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout.strip())
    except (json.JSONDecodeError, TypeError):
        return None


def get_image_config(image_name: str) -> dict | None:
    """Extract CMD, ENTRYPOINT, ENV, WORKDIR from a Docker image.

    Returns a dict with keys: ``cmd``, ``entrypoint``, ``env``,
    ``working_dir``, ``exposed_ports``.  Returns ``None`` if the
    image cannot be inspected.

    Example::

        cfg = get_image_config("my-env:latest")
        # cfg = {
        #     "cmd": ["uvicorn", "app:app", "--host", "0.0.0.0"],
        #     "entrypoint": None,
        #     "env": {"PATH": "...", "MY_VAR": "value"},
        #     "working_dir": "/app",
        #     "exposed_ports": [8000],
        # }
    """
    # Ensure image is available locally, pulling if needed
    try:
        _pull_or_check_local(image_name)
    except RuntimeError:
        return None

    result = subprocess.run(
        ["docker", "inspect", "--format", "{{json .Config}}", image_name],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return None
    try:
        config = json.loads(result.stdout.strip())
    except (json.JSONDecodeError, TypeError):
        return None

    # Parse env list ["KEY=VALUE", ...] into dict
    env_dict: dict[str, str] = {}
    for entry in config.get("Env") or []:
        key, _, value = entry.partition("=")
        env_dict[key] = value

    # Parse ExposedPorts {"8000/tcp": {}, ...} into list of ints
    ports: list[int] = []
    for port_proto in config.get("ExposedPorts") or {}:
        port_str = port_proto.split("/")[0]
        try:
            ports.append(int(port_str))
        except ValueError:
            pass

    return {
        "cmd": config.get("Cmd"),
        "entrypoint": config.get("Entrypoint"),
        "env": env_dict,
        "working_dir": config.get("WorkingDir") or None,
        "exposed_ports": ports,
    }


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
        cache_dir: Root cache directory (e.g. ``~/.cache/agentdocker_lite/rootfs``).
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
        layer_dirs = [layers_dir / _safe_cache_key(did) for did in diff_ids]
        if all(d.exists() for d in layer_dirs):
            logger.info("All %d layers cached for %s", len(layer_dirs), image_name)
            return layer_dirs

    # Need image metadata — pull if requested, then get diff_ids
    if pull:
        _pull_or_check_local(image_name)

    diff_ids = _get_image_diff_ids(image_name)
    if not diff_ids:
        raise RuntimeError(
            f"Cannot get layer diff_ids for {image_name!r}. "
            f"Ensure Docker is available and the image exists."
        )

    # Check again with fresh diff_ids (image may have been updated)
    layer_dirs = [layers_dir / _safe_cache_key(did) for did in diff_ids]
    if all(d.exists() for d in layer_dirs):
        logger.info("All %d layers cached for %s", len(layer_dirs), image_name)
        _write_manifest(cache_dir, image_name, diff_ids)
        return layer_dirs

    # Need to extract — use docker save
    logger.info("Extracting layers for %s (%d layers, %d cached)",
                image_name, len(diff_ids),
                sum(1 for d in layer_dirs if d.exists()))

    save_proc = subprocess.Popen(
        ["docker", "save", image_name],
        stdout=subprocess.PIPE,
    )
    with tarfile.open(fileobj=save_proc.stdout, mode="r|") as outer_tar:
        _extract_layers_from_save_tar(outer_tar, diff_ids, layers_dir)
    save_proc.wait()
    if save_proc.returncode != 0:
        raise RuntimeError(f"docker save failed for {image_name!r}")

    _write_manifest(cache_dir, image_name, diff_ids)
    logger.info("Layer cache ready for %s: %d layers", image_name, len(layer_dirs))
    return layer_dirs


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


def _extract_single_layer_locked(
    raw: bytes,
    layer_dir: Path,
    layers_dir: Path,
) -> None:
    """Extract a single layer tarball with file locking for concurrent safety."""
    import shutil

    lock_path = layers_dir / f".{layer_dir.name}.lock"
    tmp_dir = layer_dir.with_suffix(".extracting")
    with open(lock_path, "w") as lock_fd:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        try:
            if layer_dir.exists():
                return  # Another process extracted while we waited

            if tmp_dir.exists():
                shutil.rmtree(tmp_dir)
            tmp_dir.mkdir(parents=True)

            # Extract tar (use "tar" filter not "data" — rootfs layers
            # contain absolute symlinks which "data" rejects)
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as lt:
                lt.extractall(tmp_dir, filter="tar")

            # Convert OCI whiteouts to overlayfs whiteouts
            _convert_whiteouts_in_layer(tmp_dir)

            # Atomic rename
            tmp_dir.rename(layer_dir)
            logger.debug("Extracted layer: %s", layer_dir.name)
        except Exception:
            # Clean up partial extraction
            if tmp_dir.exists():
                shutil.rmtree(tmp_dir, ignore_errors=True)
            raise
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
    # Clean up lock file (best effort)
    try:
        lock_path.unlink()
    except OSError:
        pass


def _get_manifest_diff_ids(
    cache_dir: Path,
    image_name: str,
) -> list[str] | None:
    """Read cached manifest to get diff_ids without docker inspect."""
    safe_name = image_name.replace("/", "_").replace(":", "_").replace(".", "_")
    manifest_path = cache_dir / "manifests" / f"{safe_name}.json"
    if not manifest_path.exists():
        return None
    try:
        data = json.loads(manifest_path.read_text())
        return data.get("diff_ids")
    except (json.JSONDecodeError, OSError):
        return None


def _write_manifest(
    cache_dir: Path,
    image_name: str,
    diff_ids: list[str],
) -> None:
    """Write manifest mapping image name to its layer diff_ids."""
    manifests_dir = cache_dir / "manifests"
    manifests_dir.mkdir(parents=True, exist_ok=True)
    safe_name = image_name.replace("/", "_").replace(":", "_").replace(".", "_")
    manifest_path = manifests_dir / f"{safe_name}.json"
    manifest_path.write_text(json.dumps({
        "image": image_name,
        "diff_ids": diff_ids,
        "layers": [_safe_cache_key(did) for did in diff_ids],
    }, indent=2))


def _pull_or_check_local(image_name: str) -> None:
    """Ensure image is available locally, pulling only if needed."""
    # Check local first (like `docker run` behavior)
    check = subprocess.run(
        ["docker", "image", "inspect", image_name],
        capture_output=True,
    )
    if check.returncode == 0:
        logger.debug("Image exists locally: %s", image_name)
        return

    # Not local — pull
    logger.info("Pulling image: %s", image_name)
    result = subprocess.run(
        ["docker", "pull", image_name],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"docker pull failed: {result.stderr.strip()}")


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

    if pull:
        _pull_or_check_local(image_name)

    logger.info("Creating temporary container from %s", image_name)
    create = subprocess.run(
        ["docker", "create", image_name],
        capture_output=True,
        text=True,
    )
    if create.returncode != 0:
        raise RuntimeError(f"docker create failed: {create.stderr.strip()}")
    container_id = create.stdout.strip()

    try:
        logger.info("Exporting %s -> %s", image_name, output_dir)
        export_proc = subprocess.Popen(
            ["docker", "export", container_id],
            stdout=subprocess.PIPE,
        )
        tar_proc = subprocess.Popen(
            ["tar", "-C", str(output_dir), "-xf", "-"],
            stdin=export_proc.stdout,
        )
        if export_proc.stdout is not None:
            export_proc.stdout.close()
        tar_proc.communicate()

        if tar_proc.returncode != 0:
            raise RuntimeError(
                f"tar extraction failed for {image_name} (exit {tar_proc.returncode})"
            )
    finally:
        subprocess.run(["docker", "rm", "-f", container_id], capture_output=True)

    subprocess.run(["docker", "rmi", "-f", image_name], capture_output=True)

    logger.info("Rootfs ready: %s", output_dir)
    return output_dir


def prepare_rootfs_without_docker(
    image_ref: str,
    output_dir: str | Path,
) -> Path:
    """Export an OCI image as a rootfs without requiring a Docker daemon.

    Uses ``skopeo`` + ``umoci`` which can run without root and without
    a running Docker daemon.

    Args:
        image_ref: OCI image reference (e.g. ``"docker://ubuntu:22.04"``).
        output_dir: Target directory for the extracted rootfs.

    Returns:
        Path to the rootfs bundle directory.

    Raises:
        RuntimeError: If skopeo/umoci commands fail.
        FileNotFoundError: If skopeo or umoci is not installed.
    """
    import shutil
    import tempfile

    for tool in ("skopeo", "umoci"):
        if shutil.which(tool) is None:
            raise FileNotFoundError(
                f"{tool} not found. Install it: apt-get install {tool}"
            )

    output_dir = Path(output_dir)

    with tempfile.TemporaryDirectory() as tmp:
        oci_dir = Path(tmp) / "oci_image"

        if not image_ref.startswith("docker://"):
            image_ref = f"docker://{image_ref}"

        logger.info("Copying %s via skopeo", image_ref)
        result = subprocess.run(
            ["skopeo", "copy", image_ref, f"oci:{oci_dir}:latest"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"skopeo copy failed: {result.stderr.strip()}")

        logger.info("Unpacking OCI image via umoci -> %s", output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["umoci", "unpack", "--image", f"{oci_dir}:latest", str(output_dir)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"umoci unpack failed: {result.stderr.strip()}")

    rootfs_path = output_dir / "rootfs"
    if rootfs_path.is_dir():
        logger.info("Rootfs ready: %s", rootfs_path)
        return rootfs_path

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

    if pull:
        _pull_or_check_local(image_name)

    logger.info("Creating temporary container from %s", image_name)
    create = subprocess.run(
        ["docker", "create", image_name],
        capture_output=True,
        text=True,
    )
    if create.returncode != 0:
        raise RuntimeError(f"docker create failed: {create.stderr.strip()}")
    container_id = create.stdout.strip()

    try:
        logger.info(
            "Exporting %s -> %s (btrfs subvolume)", image_name, subvolume_path
        )
        export_proc = subprocess.Popen(
            ["docker", "export", container_id],
            stdout=subprocess.PIPE,
        )
        tar_proc = subprocess.Popen(
            ["tar", "-C", str(subvolume_path), "-xf", "-"],
            stdin=export_proc.stdout,
        )
        if export_proc.stdout is not None:
            export_proc.stdout.close()
        tar_proc.communicate()

        if tar_proc.returncode != 0:
            raise RuntimeError(
                f"tar extraction failed for {image_name} (exit {tar_proc.returncode})"
            )
    finally:
        subprocess.run(["docker", "rm", "-f", container_id], capture_output=True)

    subprocess.run(["docker", "rmi", "-f", image_name], capture_output=True)

    logger.info("btrfs rootfs ready: %s", subvolume_path)
    return subvolume_path
