"""Overlayfs mount, reset, and bind-mount operations."""

from __future__ import annotations

import logging
import shutil
import tempfile
import time
from pathlib import Path

logger = logging.getLogger(__name__)


def setup_overlay(lowerdir_spec: str, upper_dir: str, work_dir: str, rootfs: str) -> None:
    """Mount overlayfs with the given layer stack."""
    from nitrobox._backend import py_mount_overlay

    for d in (upper_dir, work_dir, rootfs):
        Path(d).mkdir(parents=True, exist_ok=True)

    py_mount_overlay(
        lowerdir_spec,
        upper_dir,
        work_dir,
        rootfs,
    )

    from nitrobox._backend import py_make_private
    try:
        py_make_private(rootfs)
    except OSError:
        pass

    logger.debug("Mounted overlayfs at %s", rootfs)


def reset_overlayfs(
    rootfs: str,
    upper_dir: str,
    work_dir: str,
    lowerdir_spec: str,
    *,
    overlay_mounted: bool = False,
    cleanup_dead_dirs: list[Path] | None = None,
) -> None:
    """Reset overlayfs by clearing upper layer and remounting.

    Parameters:
        rootfs: Mount point for the overlay filesystem.
        upper_dir: Path to the upper (writable) layer.
        work_dir: Path to the overlayfs work directory.
        lowerdir_spec: Colon-separated lower directory specification.
        overlay_mounted: Whether the overlay is currently mounted.
        cleanup_dead_dirs: Optional list of dead directories to clean up.
    """
    if overlay_mounted:
        from nitrobox._backend import py_umount_lazy
        try:
            py_umount_lazy(rootfs)
        except OSError:
            pass

    # Clean up any leftover dead dirs
    if cleanup_dead_dirs:
        for dead in cleanup_dead_dirs:
            if dead.exists():
                shutil.rmtree(dead, ignore_errors=True)

    for d_str in (upper_dir, work_dir):
        d = Path(d_str)
        if d.exists():
            dead = d.with_name(f"{d.name}.dead.{time.monotonic_ns()}")
            try:
                d.rename(dead)
            except OSError:
                shutil.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True, exist_ok=True)

    setup_overlay(lowerdir_spec, upper_dir, work_dir, rootfs)


def bind_mount(
    host_path: str,
    container_path: str,
    rootfs: str,
    *,
    read_only: bool = False,
) -> Path | None:
    """Bind-mount a host path into the container rootfs.

    Returns the target mount point path on success, or ``None`` on failure.
    """
    from nitrobox._backend import py_bind_mount, py_remount_ro_bind

    target = Path(rootfs) / container_path.lstrip("/")
    target.mkdir(parents=True, exist_ok=True)

    try:
        py_bind_mount(host_path, str(target))
    except OSError as e:
        logger.warning("Failed to bind mount %s -> %s: %s",
                       host_path, container_path, e)
        return None

    if read_only:
        try:
            py_remount_ro_bind(str(target))
        except OSError:
            pass

    return target


def overlay_mount(
    host_path: str,
    container_path: str,
    rootfs: str,
) -> tuple[Path | None, str | None]:
    """Mount a host directory as copy-on-write via overlayfs.

    Returns:
        A tuple of ``(target_mount_point, tmpdir)`` on success, or
        ``(None, None)`` on failure.  The caller should track *tmpdir*
        for cleanup.
    """
    from nitrobox._backend import py_mount_overlay

    target = Path(rootfs) / container_path.lstrip("/")
    target.mkdir(parents=True, exist_ok=True)

    work_base = tempfile.mkdtemp(prefix="nbx_cow_")
    upper = Path(work_base) / "upper"
    work = Path(work_base) / "work"
    upper.mkdir()
    work.mkdir()

    try:
        py_mount_overlay(str(host_path), str(upper), str(work), str(target))
    except OSError as e:
        logger.warning("Failed to overlay mount %s -> %s: %s",
                       host_path, container_path, e)
        return None, None

    return target, work_base


def unmount_binds(
    bind_mounts: list[Path],
    cow_tmpdirs: list[str] | None = None,
) -> None:
    """Unmount all bind mounts and clean up COW temp directories."""
    from nitrobox._backend import py_umount_lazy

    for mount_point in reversed(bind_mounts):
        try:
            py_umount_lazy(str(mount_point))
        except OSError:
            pass
    bind_mounts.clear()

    if cow_tmpdirs:
        for tmpdir in cow_tmpdirs:
            shutil.rmtree(tmpdir, ignore_errors=True)
        cow_tmpdirs.clear()


def unmount_all(
    rootfs: str,
    bind_mounts: list[Path],
    cow_tmpdirs: list[str] | None = None,
    *,
    fs_backend: str = "overlayfs",
    overlay_mounted: bool = False,
) -> None:
    """Unmount bind mounts, then the root overlay if applicable."""
    from nitrobox._backend import py_umount_recursive_lazy

    unmount_binds(bind_mounts, cow_tmpdirs)

    if fs_backend == "overlayfs" and overlay_mounted:
        try:
            py_umount_recursive_lazy(rootfs)
        except OSError:
            pass
