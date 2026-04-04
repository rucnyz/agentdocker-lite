"""Shared fixtures for nitrobox tests."""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest


def _umount_stale_overlays(root: str) -> None:
    """Umount any overlay mounts under *root* via the setuid helper."""
    result = subprocess.run(["mount"], capture_output=True, text=True)
    mounts = [
        line.split(" on ")[1].split(" type ")[0]
        for line in result.stdout.splitlines()
        if root in line and " on " in line
    ]
    if not mounts:
        return
    try:
        from nitrobox.checkpoint import _find_helper
        helper = _find_helper()
    except (FileNotFoundError, ImportError):
        return
    for mnt in mounts:
        subprocess.run([helper, "umount", mnt], capture_output=True, timeout=5)


@pytest.fixture(scope="session", autouse=True)
def _cleanup_previous_garbage():
    """Clean up garbage dirs from previous pytest runs.

    Pytest moves old tmp dirs to ``garbage-*`` on startup, but can't
    delete files with mapped UIDs (from userns layer extraction) or
    stale overlay mounts (from checkpoint tests).  Umount first, then
    rmtree_mapped.
    """
    import glob
    from pathlib import Path

    garbage_root = Path(f"/tmp/pytest-of-{os.environ.get('USER', 'root')}")
    for garbage in glob.glob(str(garbage_root / "garbage-*")):
        _umount_stale_overlays(garbage)
        try:
            from nitrobox.image.layers import rmtree_mapped
            rmtree_mapped(garbage)
        except Exception:
            pass


@pytest.fixture(scope="session")
def shared_cache_dir(tmp_path_factory):
    """Session-scoped rootfs cache shared by all tests.

    Avoids re-extracting Docker image layers per-test (~80 MB each),
    which quickly fills tmpfs on repeated runs.
    """
    cache = tmp_path_factory.mktemp("rootfs_cache")
    yield str(cache)
    # Layers may contain files with mapped UIDs (userns extraction).
    from nitrobox.image.layers import rmtree_mapped
    rmtree_mapped(str(cache))


def _find_stale_mounts(path: str) -> list[str]:
    """Return list of active bind mounts under *path*."""
    result = subprocess.run(["mount"], capture_output=True, text=True)
    return [
        line for line in result.stdout.splitlines()
        if path in line
    ]


def _find_stale_processes(env_dir: str) -> list[int]:
    """Return PIDs that still reference *env_dir* (via /proc/*/root)."""
    stale: list[int] = []
    pid_file = os.path.join(env_dir, ".pid")
    if not os.path.exists(pid_file):
        return stale
    try:
        pid = int(open(pid_file).read().strip())
        # Check if process is alive
        os.kill(pid, 0)
        stale.append(pid)
    except (ValueError, OSError, ProcessLookupError):
        pass
    return stale


@pytest.fixture(autouse=True)
def _assert_clean_after_test(request, tmp_path):
    """After every test, assert that no sandbox resources leaked.

    Checks:
    - No bind mounts left under tmp_path (e.g. .netns, overlayfs)
    - No sandbox env directories left with stale .pid files
    - tmp_path can be fully removed (no "Directory not empty")
    """
    yield

    # Only check tests that used tmp_path for sandbox env_dirs
    envs_dir = tmp_path / "envs"
    if not envs_dir.exists():
        return

    errors: list[str] = []

    # 1. Check for stale bind mounts
    stale_mounts = _find_stale_mounts(str(tmp_path))
    if stale_mounts:
        # Try to clean up via setuid helper (non-root can't umount
        # root-created mounts from checkpoint restore).
        _umount_stale_overlays(str(tmp_path))
        # Fallback: plain umount -l for non-overlay mounts
        remaining = _find_stale_mounts(str(tmp_path))
        for mount_line in remaining:
            mount_point = mount_line.split(" on ")[1].split(" type ")[0] if " on " in mount_line else ""
            if mount_point:
                subprocess.run(["umount", "-l", mount_point], capture_output=True)
        errors.append(
            f"Stale bind mounts after test: {stale_mounts}"
        )

    # 2. Check for leftover env directories with .pid files (zombie sandboxes)
    for entry in envs_dir.iterdir():
        if not entry.is_dir():
            continue
        stale_pids = _find_stale_processes(str(entry))
        if stale_pids:
            errors.append(
                f"Stale sandbox process(es) in {entry.name}: pids={stale_pids}"
            )

    # 3. Verify tmp_path is cleanly removable (no stuck files)
    try:
        from nitrobox.image.layers import rmtree_mapped
        rmtree_mapped(str(envs_dir))
    except OSError as e:
        errors.append(f"Cannot clean env dir: {e}")

    if errors:
        pytest.fail(
            "Resource leak detected after test:\n" + "\n".join(f"  - {e}" for e in errors)
        )
